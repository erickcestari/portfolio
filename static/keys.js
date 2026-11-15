// Keyboard shortcuts: j / k step through the post list, t switches theme,
// ? lists these, Esc closes the list. And a secret word: typing "satoshi"
// asks the sky for a meteor shower. A "t" in the middle of the word is a
// letter, not the theme shortcut, so the word can be typed in peace.

const SECRET = "satoshi";
const PAUSE_MS = 1500; // a longer gap between letters starts the word over

const HELP = `+-- keys ---------------------------+
|                                   |
|   j  k    next / previous post    |
|   t       switch theme            |
|   ?       this list               |
|   esc     close                   |
|                                   |
+-----------------------------------+`;

let typed = "";
let lastKey = 0;

/** Follows the secret word. True when this key continued a word already
 *  under way, so it should not also act as a shortcut. */
function followWord(key) {
    const letter = key.length === 1 ? key.toLowerCase() : "";
    const at = performance.now();
    if (at - lastKey > PAUSE_MS) typed = "";
    lastKey = at;

    const continuing = typed !== "" && letter !== "" && SECRET.startsWith(typed + letter);
    typed = continuing ? typed + letter : SECRET.startsWith(letter) && letter ? letter : "";
    if (typed === SECRET) {
        typed = "";
        dispatchEvent(new CustomEvent("sky:shower"));
    }
    return continuing;
}

/** Moves focus to the next (+1) or previous (-1) post the list is showing. */
function step(by) {
    const posts = [...document.querySelectorAll(".ledger-row:not([hidden]) .ledger-title")];
    if (posts.length === 0) return false;
    const at = posts.indexOf(document.activeElement);
    const next = at === -1 ? 0 : Math.min(posts.length - 1, Math.max(0, at + by));
    posts[next].focus();
    return true;
}

let help = null;

function toggleHelp() {
    if (!help) {
        help = document.createElement("dialog");
        help.className = "keys-help";
        help.setAttribute("aria-label", "Keyboard shortcuts");
        const art = document.createElement("pre");
        art.textContent = HELP;
        help.append(art);
        // A click on the backdrop lands on the dialog itself: close.
        help.addEventListener("click", (event) => {
            if (event.target === help) help.close();
        });
        document.body.append(help);
    }
    if (help.open) help.close();
    else help.showModal();
}

addEventListener("keydown", (event) => {
    if (event.defaultPrevented || event.ctrlKey || event.metaKey || event.altKey) return;
    if (event.target.closest?.("input, textarea, select, [contenteditable]")) return;
    if (followWord(event.key)) return;

    let handled = true;
    switch (event.key) {
        case "j":
            handled = step(1);
            break;
        case "k":
            handled = step(-1);
            break;
        case "t":
            document.querySelector(".theme-toggle")?.click();
            break;
        case "?":
            toggleHelp();
            break;
        default:
            handled = false;
    }
    if (handled) event.preventDefault();
});
