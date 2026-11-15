// The 404 page: the missing path's SHA-256 as the block bitcoin-cli failed to
// find, and a guess at the page the visitor meant.

// ---- The block asked for ----

// crypto.subtle needs a secure context; elsewhere the zero hash stays.
if (crypto.subtle) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(location.pathname));
    document.querySelector(".cli-hash").textContent =
        [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---- Did you mean ----

// Close enough to suggest: the best page must match about half the address.
const THRESHOLD = 0.45;

const words = (path) => path.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

function editDistance(a, b) {
    let row = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
        const next = [i];
        for (let j = 1; j <= b.length; j++) {
            next[j] = Math.min(row[j] + 1, next[j - 1] + 1, row[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
        }
        row = next;
    }
    return row[b.length];
}

/** 0 to 1: how well the words of `asked` match those of `page`, each asked
 *  word scored against its nearest page word, so "btcd-oom" finds
 *  "btcd-reject-oom" and "boks" finds "books". */
function closeness(asked, page) {
    const a = words(asked);
    const p = words(page);
    if (a.length === 0 || p.length === 0) return 0;
    const near = (w) => Math.max(...p.map((x) => 1 - editDistance(w, x) / Math.max(w.length, x.length)));
    return a.reduce((sum, w) => sum + near(w), 0) / Math.max(a.length, p.length);
}

const pages = [...document.querySelector(".known-pages").content.querySelectorAll("a")];
const best = pages
    .map((page) => ({ page, score: closeness(location.pathname, page.getAttribute("href")) }))
    .reduce((a, b) => (b.score > a.score ? b : a), { page: null, score: 0 });

if (best.page && best.score >= THRESHOLD) {
    const hint = document.querySelector(".did-you-mean");
    const link = hint.querySelector("a");
    link.href = best.page.getAttribute("href");
    link.textContent = best.page.textContent;
    hint.hidden = false;
}
