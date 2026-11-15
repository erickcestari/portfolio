// The site's [copy] button: it copies a value when pressed and says how that
// went for a moment, "copied!" or "failed". Code blocks (post.js) and the
// footer's address and fingerprint (footer.js) share it.

/** A button that copies `value()` when pressed, read then, not when built.
 *  `label` names it for screen readers; the live text reports the result. */
export function copyButton(value, label, className) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = className;
    button.textContent = "copy";
    button.setAttribute("aria-label", label);
    button.setAttribute("aria-live", "polite");

    let reset = 0;
    const show = (word) => {
        button.textContent = word;
        clearTimeout(reset);
        reset = setTimeout(() => (button.textContent = "copy"), 1500);
    };
    button.addEventListener("click", () => {
        const copied = navigator.clipboard?.writeText(value()) ?? Promise.reject();
        copied.then(() => show("copied!"), () => show("failed"));
    });
    return button;
}
