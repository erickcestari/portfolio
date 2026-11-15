// The sky's script. It draws tonight's moon in ASCII, and on every page load
// casts a new sky: a varying number of stars anywhere, and whichever of the
// moon (or sun) and the two constellations are out somewhere in the side
// margins, clear of the text, of each other and of anything fixed there.
// Without it, the stylesheet's fixed sky stays.
//
// Now and then a shooting star crosses the night. The calendar adds the
// rest: snow through December, and on Bitcoin's birthdays the bitcoin
// constellation is always out and a meteor shower greets the visitor.
// keys.js sets off the same shower on request.
//
// The moon is phase only, from the clock: no location, no requests. It is
// lit on the right while waxing, as seen from the northern hemisphere.

import { bitcoinDay, now } from "./today.js";

const SYNODIC_DAYS = 29.530588853;
// A known new moon (2000-01-06 18:14 UTC), the start of a cycle.
const NEW_MOON = Date.UTC(2000, 0, 6, 18, 14);

const ROWS = 9;
const COLS = 17;
// A monospace cell at the moon's line-height, in em: 0.6 wide, 1.1 tall, so
// 17 columns by 9 rows make a round disk.
const CELL_W = 0.6;
const CELL_H = 1.1;
const RADIUS = (ROWS * CELL_H) / 2;
const SAMPLES = 4; // per cell side, to grade the edges

// The darker seas, roughly where they sit on the near side: x, y, radius in
// units of the moon's radius, y down.
const MARIA = [
    [-0.32, -0.38, 0.3], // Imbrium
    [0.12, -0.32, 0.2],  // Serenitatis
    [0.3, 0.02, 0.24],   // Tranquillitatis
    [-0.58, 0.02, 0.32], // Procellarum
    [-0.12, 0.42, 0.2],  // Nubium
];

/** Fraction of the cycle since new moon: 0 new, 0.25 first quarter, 0.5 full. */
export function phaseAt(ms) {
    const cycles = (ms - NEW_MOON) / 86400000 / SYNODIC_DAYS;
    return cycles - Math.floor(cycles);
}

function lit(x, y, phase) {
    // The terminator is a half-ellipse; cos sweeps it across the disk, from
    // the right edge at new moon to the left at full and back.
    const edge = Math.cos(2 * Math.PI * phase) * Math.sqrt(1 - y * y);
    return phase < 0.5 ? x > edge : x < -edge;
}

function inSea(x, y) {
    return MARIA.some(([cx, cy, r]) => (x - cx) ** 2 + (y - cy) ** 2 < r * r);
}

/** The moon at `phase` as text: 9 lines of 17 columns. */
export function drawMoon(phase) {
    const lines = [];
    for (let row = 0; row < ROWS; row++) {
        let line = "";
        for (let col = 0; col < COLS; col++) {
            let disk = 0;
            let light = 0;
            for (let i = 0; i < SAMPLES; i++) {
                for (let j = 0; j < SAMPLES; j++) {
                    const x = ((col + (i + 0.5) / SAMPLES - COLS / 2) * CELL_W) / RADIUS;
                    const y = ((row + (j + 0.5) / SAMPLES - ROWS / 2) * CELL_H) / RADIUS;
                    if (x * x + y * y > 1) continue;
                    disk++;
                    if (lit(x, y, phase)) light++;
                }
            }
            const n = SAMPLES * SAMPLES;
            const x = ((col + 0.5 - COLS / 2) * CELL_W) / RADIUS;
            const y = ((row + 0.5 - ROWS / 2) * CELL_H) / RADIUS;
            if (light > n * 0.55) line += inSea(x, y) ? ":" : "#";
            else if (light > n * 0.2) line += "*";
            // The unlit limb, faintly, so the whole disk still reads.
            else if (disk > n * 0.15 && disk < n * 0.9) line += ".";
            else line += " ";
        }
        lines.push(line.trimEnd());
    }
    return lines.join("\n");
}

/** `text` as a CSS string for `content`, one `\A` per line break. */
function cssString(text) {
    const escaped = text.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\A ");
    return `"${escaped}"`;
}

// ---- Scatter ----

// Each figure's box in px, as style.css's "Sky" section draws it (keep the
// two in step; the sun fits inside the moon's box), and the chance it is out
// on a given load, so the constellations stay a find rather than a fixture.
const FIGURES = {
    moon: { size: [133, 130], chance: 0.35 },
    bolt: { size: [120, 166], chance: 0.25 },
    btc: { size: [112, 172], chance: 0.25 },
};
// How many stars a load gets, inclusive.
const BRIGHT_STARS = [4, 10];
const DIM_STARS = [18, 48];
const CLEAR = 24; // px kept between a figure and anything else
const TRIES = 80;
// Where the stylesheet shows the figures at all.
const WIDE = "(min-width: 75rem)";

/** A small seeded generator (mulberry32): a resize redraws the same sky. */
function generator(seed) {
    return () => {
        seed = (seed + 0x6d2b79f5) | 0;
        let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

function overlaps(a, b, gap) {
    return a.left < b.right + gap && b.left < a.right + gap
        && a.top < b.bottom + gap && b.top < a.bottom + gap;
}

/** Puts each figure that is out in a free spot of either side margin, and
 *  hides the rest, plus any with no room this load. Returns the boxes used. */
function placeFigures(random, out, style) {
    const column = document.body.getBoundingClientRect();
    const taken = [...document.querySelectorAll(".toc, .read-progress, .to-top")]
        .filter((el) => getComputedStyle(el).position === "fixed")
        .map((el) => el.getBoundingClientRect());
    const placed = [];
    for (const [name, { size: [width, height] }] of Object.entries(FIGURES)) {
        let spot = null;
        for (let i = 0; i < TRIES && out[name] && !spot; i++) {
            const onLeft = random() < 0.5;
            const minX = onLeft ? CLEAR : column.right + CLEAR;
            const maxX = (onLeft ? column.left : innerWidth) - CLEAR - width;
            const maxY = innerHeight - CLEAR - height;
            if (maxX < minX || maxY < CLEAR) continue;
            const left = minX + random() * (maxX - minX);
            const top = CLEAR + random() * (maxY - CLEAR);
            const box = { left, top, right: left + width, bottom: top + height };
            if (![...taken, ...placed].some((other) => overlaps(box, other, CLEAR))) spot = box;
        }
        style.setProperty(`--${name}-display`, spot ? "block" : "none");
        if (spot) {
            style.setProperty(`--${name}-left`, `${spot.left.toFixed(0)}px`);
            style.setProperty(`--${name}-top`, `${spot.top.toFixed(0)}px`);
            placed.push(spot);
        }
    }
    return placed;
}

// Glyph, font size and opacity of a star, drawn as the stylesheet's own.
const brightStar = (random) =>
    random() < 0.6 ? ["*", 13, 0.65 + random() * 0.1] : ["+", 11, 0.55 + random() * 0.05];
const dimStar = (random) => {
    const roll = random();
    const [glyph, size] = roll < 0.5 ? [".", 12] : roll < 0.75 ? ["'", 12] : ["+", 9];
    return [glyph, size, 0.25 + random() * 0.25];
};

/** An SVG layer of `count` stars at % positions, kept off the figures so a
 *  stray star never blurs a constellation's shape. */
function starLayer(random, count, star, figures) {
    let svg = "<svg xmlns='http://www.w3.org/2000/svg' width='100%' height='100%' "
        + "font-family='monospace' fill='#ece7df'>";
    for (let n = 0; n < count; n++) {
        let x = random();
        let y = random();
        for (let i = 0; i < TRIES; i++) {
            const at = { left: x * innerWidth, top: y * innerHeight };
            at.right = at.left;
            at.bottom = at.top;
            if (!figures.some((box) => overlaps(at, box, 8))) break;
            x = random();
            y = random();
        }
        const [glyph, size, opacity] = star(random);
        svg += `<text x='${(x * 100).toFixed(1)}%' y='${(y * 100).toFixed(1)}%' `
            + `font-size='${size}' opacity='${opacity.toFixed(2)}'>${glyph}</text>`;
    }
    return `url("data:image/svg+xml,${encodeURIComponent(svg + "</svg>")}")`;
}

// ---- Shooting stars, meteor shower and snow ----

const TRAIL = "-------------";
const SHOWER_METEORS = 16;
const FLAKES = 48;

/** How far "*" sits above the middle of a "-" in `el`'s face, in px. Every
 *  face raises the asterisk by its own amount, so it is measured, not guessed. */
function asteriskRise(el) {
    const { fontSize, fontFamily } = getComputedStyle(el);
    // Measured at 100px and scaled down: glyph boxes come back in whole pixels,
    // too coarse at the meteor's own size.
    const pen = document.createElement("canvas").getContext("2d");
    pen.font = `100px ${fontFamily}`;
    const middle = (glyph) => {
        const box = pen.measureText(glyph);
        return (box.actualBoundingBoxAscent - box.actualBoundingBoxDescent) / 2;
    };
    return ((middle("*") - middle("-")) * parseFloat(fontSize)) / 100;
}

let headDrop = null;

/** A streak from (left vw, top vh) down and to the left: a "*" head dropped
 *  into line with its "-" trail, gone once it has crossed. The stylesheet
 *  draws it (".meteor"); an ambient one keeps to the night, behind the text. */
function launch(left, top, delay, ambient) {
    const meteor = document.createElement("span");
    meteor.className = ambient ? "meteor is-ambient" : "meteor";
    meteor.setAttribute("aria-hidden", "true");
    const head = document.createElement("span");
    head.className = "meteor-head";
    head.textContent = "*";
    meteor.append(head, TRAIL);
    meteor.style.left = `${left.toFixed(1)}vw`;
    meteor.style.top = `${top.toFixed(1)}vh`;
    meteor.style.animationDelay = `${delay.toFixed(2)}s`;
    meteor.addEventListener("animationend", () => meteor.remove());
    document.body.append(meteor);
    if (headDrop === null) {
        headDrop = asteriskRise(meteor);
        document.documentElement.style.setProperty("--meteor-drop", `${headDrop.toFixed(1)}px`);
    }
}

/** A burst of shooting stars across the upper sky, in either theme. */
function shower() {
    for (let n = 0; n < SHOWER_METEORS; n++) {
        launch(30 + Math.random() * 70, Math.random() * 45, Math.random() * 2.4, false);
    }
}

/** One shooting star every 8 to 18 seconds, in the upper right of the night. */
function shootingStars() {
    setTimeout(() => {
        launch(55 + Math.random() * 35, 5 + Math.random() * 25, 0, true);
        shootingStars();
    }, 8000 + Math.random() * 10000);
}

/** Flakes of "*" and "." drifting down behind the page, already mid-fall
 *  when it loads: a negative delay starts each one partway down. */
function snow() {
    const field = document.createElement("div");
    field.className = "snow";
    field.setAttribute("aria-hidden", "true");
    for (let n = 0; n < FLAKES; n++) {
        const flake = document.createElement("span");
        const fall = 12 + Math.random() * 18; // seconds to cross the screen
        flake.textContent = Math.random() < 0.6 ? "*" : ".";
        flake.style.left = `${(Math.random() * 100).toFixed(1)}%`;
        flake.style.fontSize = `${(10 + Math.random() * 6).toFixed(0)}px`;
        flake.style.opacity = (0.3 + Math.random() * 0.5).toFixed(2);
        flake.style.animationDuration = `${fall.toFixed(1)}s`;
        flake.style.animationDelay = `${(-Math.random() * fall).toFixed(1)}s`;
        flake.style.setProperty("--sway", `${((Math.random() - 0.5) * 12).toFixed(1)}vw`);
        field.append(flake);
    }
    document.body.append(field);
}

if (typeof document !== "undefined") {
    const root = document.documentElement;
    const today = now();
    const occasion = bitcoinDay(today);
    root.style.setProperty("--moon-art", cssString(drawMoon(phaseAt(today.getTime()))));

    // Tonight's cast is drawn once per load: which figures are out and how
    // many stars. Placement then runs from its own seed, so a resize moves
    // things to fit without changing what is in the sky.
    const draw = generator(Math.floor(Math.random() * 2 ** 32));
    const between = ([min, max]) => min + Math.floor(draw() * (max - min + 1));
    const out = Object.fromEntries(
        Object.entries(FIGURES).map(([name, { chance }]) => [name, draw() < chance]),
    );
    // On Bitcoin's birthdays the bitcoin sign is always out.
    if (occasion) out.btc = true;
    const brightCount = between(BRIGHT_STARS);
    const dimCount = between(DIM_STARS);
    const seed = Math.floor(draw() * 2 ** 32);

    const scatter = () => {
        const random = generator(seed);
        const figures = matchMedia(WIDE).matches ? placeFigures(random, out, root.style) : [];
        root.style.setProperty("--stars-bright", starLayer(random, brightCount, brightStar, figures));
        root.style.setProperty("--stars-dim", starLayer(random, dimCount, dimStar, figures));
        root.dataset.sky = "scattered";
    };
    scatter();

    let frame = 0;
    addEventListener("resize", () => {
        cancelAnimationFrame(frame);
        frame = requestAnimationFrame(scatter);
    });

    addEventListener("sky:shower", shower);
    shootingStars();
    if (occasion) shower();
    if (today.getMonth() === 11) snow();
}
