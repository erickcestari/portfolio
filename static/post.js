// The post page's behaviours: the reading-progress bar, which also opens the
// contents from anywhere in the post; an offer to continue where the reader
// left off; heading links that copy themselves; the contents entry for the
// section named in the URL, marked as current; a [copy] button on each code
// block; and figures that open full size when scaled down.

import { copyButton } from "./copy.js";

const article = document.querySelector("article");
const toc = document.querySelector(".toc");
const toast = document.querySelector(".toast");
let hideToast = 0;

/** Shows `text` in the toast for a moment; its role lets screen readers hear it. */
function say(text) {
    toast.textContent = text;
    toast.classList.add("is-shown");
    clearTimeout(hideToast);
    hideToast = setTimeout(() => toast.classList.remove("is-shown"), 1600);
}

/** A modal panel that closes on Esc (natively), on its backdrop, or on any
 *  link inside it, which then goes where it points. Open it with `show`. */
function panel(className, label) {
    const dialog = document.createElement("dialog");
    dialog.className = className;
    dialog.setAttribute("aria-label", label);
    dialog.tabIndex = -1;
    dialog.addEventListener("click", (event) => {
        if (event.target === dialog || event.target.closest("a")) dialog.close();
    });
    document.body.append(dialog);
    return dialog;
}

/** Opens `dialog` with focus on the panel itself rather than its first link,
 *  which would ring an entry nobody chose; Tab still reaches the links. */
function show(dialog) {
    dialog.showModal();
    dialog.focus();
}

// ---- Reading progress, measured to the end of the article rather than the
// page, so the footer does not count ----

const bar = document.querySelector(".read-progress");
const CELLS = 20;

/** How far through the article the reader is, 0 to 1. */
function progress() {
    const end = article.getBoundingClientRect().bottom + scrollY - innerHeight;
    return end > 0 ? Math.min(1, Math.max(0, scrollY / end)) : 1;
}

/** The scroll position at `fraction` of the article. */
function positionAt(fraction) {
    return fraction * (article.getBoundingClientRect().bottom + scrollY - innerHeight);
}

let queued = false;
const drawProgress = () => {
    queued = false;
    const done = progress();
    const filled = Math.round(done * CELLS);
    const percent = String(Math.round(done * 100)).padStart(3);
    const hint = toc ? "  [toc]" : "";
    bar.textContent = `[${"#".repeat(filled)}${"-".repeat(CELLS - filled)}] ${percent}%${hint}`;
    bar.classList.toggle("is-reading", scrollY > 0);
    remember(done);
};
addEventListener("scroll", () => {
    if (!queued) {
        queued = true;
        requestAnimationFrame(drawProgress);
    }
}, { passive: true });
addEventListener("resize", drawProgress);

// ---- Contents: from the progress bar anywhere in the post, and the entry
// for the section in the URL marked as current ----

function markCurrentSection() {
    const hash = decodeURIComponent(location.hash);
    for (const link of document.querySelectorAll(".toc a[href^='#'], .contents-sheet a[href^='#']")) {
        if (link.getAttribute("href") === hash) link.setAttribute("aria-current", "location");
        else link.removeAttribute("aria-current");
    }
}
addEventListener("hashchange", markCurrentSection);

if (toc) {
    const sheet = panel("contents-sheet", "Contents");
    sheet.append(toc.querySelector("ul").cloneNode(true));
    bar.disabled = false;
    bar.addEventListener("click", () => show(sheet));
}
markCurrentSection();

// ---- Where the reader left off: kept on this device only ----

const PLACE_KEY = `read:${location.pathname}`;
const PLACE_DAYS = 60; // older than this, the offer is stale
let lastSaved = 0;

/** Saves the reader's place at most once a second; finishing forgets it. */
function remember(done) {
    const now = Date.now();
    if (now - lastSaved < 1000) return;
    lastSaved = now;
    try {
        if (done > 0.97) localStorage.removeItem(PLACE_KEY);
        else if (done > 0.05) localStorage.setItem(PLACE_KEY, JSON.stringify({ at: done, saved: now }));
    } catch { /* private mode: nothing to keep */ }
}

function savedPlace() {
    try {
        const place = JSON.parse(localStorage.getItem(PLACE_KEY));
        const fresh = place && Date.now() - place.saved < PLACE_DAYS * 86400000;
        return fresh && place.at > 0.05 && place.at < 0.97 ? place.at : null;
    } catch {
        return null;
    }
}

/** Offers to jump back to `at`; gone on either choice or after a while. */
function offerToResume(at) {
    const offer = document.createElement("div");
    offer.className = "resume";
    const go = document.createElement("button");
    go.type = "button";
    go.textContent = `continue at ${Math.round(at * 100)}%`;
    const dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.textContent = "x";
    dismiss.setAttribute("aria-label", "Dismiss");
    offer.append(go, dismiss);
    document.body.append(offer);

    const close = () => offer.remove();
    go.addEventListener("click", () => {
        scrollTo({ top: positionAt(at) });
        close();
    });
    dismiss.addEventListener("click", close);
    setTimeout(close, 15000);
}

// Only on a fresh arrival: a link to a section already says where to read.
const place = location.hash ? null : savedPlace();
lastSaved = Date.now(); // the load itself is not the reader moving on
drawProgress();
if (place !== null) offerToResume(place);

// ---- Headings: a click copies the section's link ----

for (const heading of article.querySelectorAll("h2[id], h3[id], h4[id]")) {
    heading.addEventListener("click", (event) => {
        if (event.target.closest("a")) return;
        // replaceState fires no hashchange, so the contents are told directly.
        history.replaceState(null, "", `#${heading.id}`);
        markCurrentSection();
        navigator.clipboard?.writeText(location.href).then(() => say("link copied"), () => {});
    });
}

// ---- Code blocks: a [copy] button ----

// The post's randomart stamp is a <pre> too, but not code.
for (const pre of article.querySelectorAll("pre:not(.stamp)")) {
    // The button sits in a frame around the block rather than inside it, so it
    // stays in the corner when a long line scrolls the code sideways.
    const frame = document.createElement("div");
    frame.className = "code";
    pre.before(frame);
    frame.append(pre, copyButton(() => pre.textContent, "Copy the code", "copy"));
}

// ---- Figures: open full size when the column scales them down ----

const zoom = panel("zoom", "Enlarged image");
const zoomed = document.createElement("img");
zoom.append(zoomed);
zoom.addEventListener("click", () => zoom.close());

for (const img of article.querySelectorAll("figure img, p > img")) {
    const open = () => {
        if (!img.classList.contains("is-zoomable")) return;
        zoomed.src = img.currentSrc || img.src;
        zoomed.alt = img.alt;
        show(zoom);
    };
    // Only worth it when at least a sixth of the detail is being lost.
    const offer = () => {
        if (img.naturalWidth < img.clientWidth * 1.2) return;
        img.classList.add("is-zoomable");
        img.tabIndex = 0;
        img.setAttribute("role", "button");
        img.setAttribute("aria-label", `Enlarge: ${img.alt}`);
    };
    if (img.complete) offer();
    else img.addEventListener("load", offer, { once: true });
    img.addEventListener("click", open);
    img.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            open();
        }
    });
}
