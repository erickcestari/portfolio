// The footer's live parts: the back-to-top link, which shows once the reader
// is half a screen down; [copy] buttons for the PGP fingerprint and the
// bitcoin address; and `$ fortune`, a different line from the footer's list
// on every load, or the day's own line on Bitcoin's birthdays.

import { copyButton } from "./copy.js";
import { bitcoinDay, now } from "./today.js";

// ---- Back to top ----

const toTop = document.querySelector(".to-top");
let queued = false;
const placeToTop = () => {
    queued = false;
    toTop.classList.toggle("is-shown", scrollY > innerHeight / 2);
};
addEventListener("scroll", () => {
    if (!queued) {
        queued = true;
        requestAnimationFrame(placeToTop);
    }
}, { passive: true });
placeToTop();

// Scrolled here rather than followed, so no "#top" is left in the address.
// Focus moves to the header, where the page starts, for keyboard readers.
toTop.addEventListener("click", (event) => {
    event.preventDefault();
    scrollTo({ top: 0 });
    document.querySelector("header a")?.focus({ preventScroll: true });
});

// ---- [copy] for the values marked data-copy ----

for (const line of document.querySelectorAll("footer [data-copy]")) {
    line.append(" ", copyButton(() => line.dataset.copy, line.dataset.copyLabel, "copy-inline"));
}

// ---- $ fortune ----

const lines = [...document.querySelector(".fortunes").content.children];
const occasion = bitcoinDay(now());
const pick = lines.find((line) => occasion && line.dataset.day === occasion)
    ?? lines[Math.floor(Math.random() * lines.length)];
const fortune = document.querySelector(".fortune");
fortune.append(pick.cloneNode(true));
fortune.hidden = false;
