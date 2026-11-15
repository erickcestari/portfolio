// Now and then an ASCII cat, kin to the one in the portrait, walks along the
// bottom of the screen, in either direction, and is gone.

// Facing right; two leg positions alternate as it walks.
const BODY = [
    " (\\           /\\_/\\",
    "  \\\\_________/ o o \\",
    "   \\___________=v=_/",
];
const LEGS = ["    ||  ||   ||  ||", "    //  \\\\   //  \\\\"];

const SPEED = 60; // px per second
const STEP_MS = 220; // how often the legs change
const FIRST = [10, 40]; // seconds before the first walk
const BETWEEN = [60, 180]; // seconds between walks

const MIRROR = { "/": "\\", "\\": "/", "(": ")", ")": "(", "<": ">", ">": "<" };

/** The cat turned to face left: each line reversed, slants and brackets swapped. */
function mirror(lines) {
    const width = Math.max(...lines.map((l) => l.length));
    return lines.map((l) => [...l.padEnd(width)].reverse().map((c) => MIRROR[c] ?? c).join(""));
}

function frames(facingLeft) {
    return LEGS.map((legs) => {
        const lines = [...BODY, legs];
        return (facingLeft ? mirror(lines) : lines).join("\n");
    });
}

const seconds = ([min, max]) => (min + Math.random() * (max - min)) * 1000;

function walk() {
    const facingLeft = Math.random() < 0.5;
    const art = frames(facingLeft);
    const cat = document.createElement("pre");
    cat.className = "cat";
    cat.setAttribute("aria-hidden", "true");
    cat.textContent = art[0];
    document.body.append(cat);

    const width = cat.offsetWidth;
    const from = facingLeft ? innerWidth : -width;
    const to = facingLeft ? -width : innerWidth;
    const duration = (Math.abs(to - from) / SPEED) * 1000;

    let frame = 0;
    const legs = setInterval(() => {
        frame = (frame + 1) % art.length;
        cat.textContent = art[frame];
    }, STEP_MS);

    cat.animate(
        [{ transform: `translateX(${from}px)` }, { transform: `translateX(${to}px)` }],
        { duration, easing: "linear" },
    ).finished.then(() => {
        clearInterval(legs);
        cat.remove();
        setTimeout(walk, seconds(BETWEEN));
    });
}

setTimeout(walk, seconds(FIRST));
