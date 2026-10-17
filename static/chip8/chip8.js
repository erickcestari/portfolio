// Plays Tetris, or a ROM the visitor loads, on the 404 page through the emuchip-8 WebAssembly module (chip8-wasm/): timing,
// input and drawing live here, emulation lives in Rust.

const FRAME_MS = 1000 / 60;
// Frames of debt to catch up after a stall before dropping the rest.
const MAX_CATCH_UP = 4;
const ROM_URL = "/chip8/tetris.ch8";

// [CHIP-8 key, KeyboardEvent.code, label]: the COSMAC VIP keypad, row by row, laid over the
// same block of a QWERTY keyboard.
const KEYPAD = [
    [0x1, "Digit1", "1"], [0x2, "Digit2", "2"], [0x3, "Digit3", "3"], [0xC, "Digit4", "4"],
    [0x4, "KeyQ", "Q"], [0x5, "KeyW", "W"], [0x6, "KeyE", "E"], [0xD, "KeyR", "R"],
    [0x7, "KeyA", "A"], [0x8, "KeyS", "S"], [0x9, "KeyD", "D"], [0xE, "KeyF", "F"],
    [0xA, "KeyZ", "Z"], [0x0, "KeyX", "X"], [0xB, "KeyC", "C"], [0xF, "KeyV", "V"],
];

const container = document.getElementById("chip8");
const canvas = document.getElementById("chip8-screen");
const keypad = document.getElementById("chip8-keypad");
const romInput = document.getElementById("chip8-rom");
const resetButton = document.getElementById("chip8-reset");
const errorLine = document.getElementById("chip8-error");

let wasm;
let rom = null; // { name, bytes } of the ROM on screen, kept for reset
let running = false;

function wasmError() {
    const bytes = new Uint8Array(wasm.memory.buffer, wasm.error_ptr(), wasm.error_len());
    return new TextDecoder().decode(bytes);
}

function halt(message) {
    running = false;
    errorLine.textContent = message;
}

function boot(next) {
    // Views over wasm memory go stale when it grows, so take them right after each call.
    const ptr = wasm.rom_buffer(next.bytes.length);
    new Uint8Array(wasm.memory.buffer, ptr, next.bytes.length).set(next.bytes);
    const [seed] = crypto.getRandomValues(new Uint32Array(1));
    if (!wasm.load(seed)) {
        halt(`${next.name}: ${wasmError()}`);
        return;
    }
    rom = next;
    errorLine.textContent = "";
    behind = 0;
    running = true;
}

// ---- Display: lit pixels in the canvas's CSS color, dark ones transparent over its background.

const ctx = canvas.getContext("2d");
let image;
let pixels;
let lit = 0;

function sizeDisplay() {
    canvas.width = wasm.display_width();
    canvas.height = wasm.display_height();
    image = ctx.createImageData(canvas.width, canvas.height);
    pixels = new Uint32Array(image.data.buffer);
}

function readLitColor() {
    const [r, g, b] = getComputedStyle(canvas).color.match(/\d+/g).map(Number);
    lit = ((255 << 24) | (b << 16) | (g << 8) | r) >>> 0; // RGBA bytes, little-endian
}

function draw() {
    const display = new Uint8Array(wasm.memory.buffer, wasm.display_ptr(), pixels.length);
    for (let i = 0; i < pixels.length; i++) pixels[i] = display[i] ? lit : 0;
    ctx.putImageData(image, 0, 0);
}

readLitColor();
new MutationObserver(readLitColor).observe(document.documentElement, { attributeFilter: ["data-theme"] });
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", readLitColor);

// ---- Input: physical keys and the on-screen keypad share one press path.

const keyByCode = new Map(KEYPAD.map(([key, code]) => [code, key]));
const buttonByKey = new Map();

function press(key, down) {
    if (wasm) wasm.set_key(key, down ? 1 : 0);
    buttonByKey.get(key).classList.toggle("chip8-down", down);
}

for (const [key, , label] of KEYPAD) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "chip8-key";
    button.setAttribute("aria-label", `key ${key.toString(16).toUpperCase()}`);
    button.innerHTML = `<span>${key.toString(16).toUpperCase()}</span><kbd>${label}</kbd>`;
    button.addEventListener("pointerdown", (e) => {
        button.setPointerCapture(e.pointerId);
        press(key, true);
    });
    button.addEventListener("pointerup", () => press(key, false));
    button.addEventListener("pointercancel", () => press(key, false));
    buttonByKey.set(key, button);
    keypad.append(button);
}

addEventListener("keydown", (e) => {
    const key = keyByCode.get(e.code);
    // Leave shortcuts such as Ctrl+R alone, and the keys themselves if the game never started.
    if (key === undefined || !running || e.ctrlKey || e.metaKey || e.altKey) return;
    e.preventDefault();
    press(key, true);
});
addEventListener("keyup", (e) => {
    const key = keyByCode.get(e.code);
    if (key !== undefined) press(key, false);
});
// A key released while the page is in the background never sends keyup.
addEventListener("blur", () => KEYPAD.forEach(([key]) => press(key, false)));

// ---- Controls

romInput.addEventListener("change", async () => {
    const [file] = romInput.files;
    romInput.value = ""; // so picking the same file again still fires
    if (file) boot({ name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) });
});
resetButton.addEventListener("click", () => boot(rom));

// ---- Main loop: fixed 60 Hz frames whatever the display's refresh rate.

let last = performance.now();
let behind = 0;

function frame(now) {
    if (running) {
        behind = Math.min(behind + now - last, MAX_CATCH_UP * FRAME_MS);
        while (running && behind >= FRAME_MS) {
            behind -= FRAME_MS;
            if (!wasm.step_frame()) halt(`${rom.name} halted: ${wasmError()}`);
        }
        draw();
    }
    last = now;
    requestAnimationFrame(frame);
}

async function fetchBytes(url) {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
    return new Uint8Array(await response.arrayBuffer());
}

try {
    const [{ instance }, tetris] = await Promise.all([
        WebAssembly.instantiateStreaming(fetch("/chip8/chip8.wasm")),
        fetchBytes(ROM_URL),
    ]);
    wasm = instance.exports;
    sizeDisplay();
    boot({ name: "Tetris", bytes: tetris });
    if (!running) throw new Error(errorLine.textContent);

    container.hidden = false;
    requestAnimationFrame(frame);
} catch (e) {
    console.error(`CHIP-8 did not start: ${e.message}`);
}
