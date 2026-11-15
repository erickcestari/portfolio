// The post list's small behaviours.
//
// Titles flicker under the pointer, or keyboard focus, like an input under a
// fuzzer: a few characters take a random bit flip, fewer each frame, until
// the title settles back to itself.
//
// Each post's block height gets an estimate of how many blocks ago it was,
// with no request: the newest post's height and day set the pace, one block
// per ten minutes since.
//
// The tags filter the list: a click on "eclair", "OOM" or "fixed" shows only
// the posts that share it, and the address keeps it (?tag=eclair), so a
// filtered list can be shared or reloaded.

const FRAMES = 7;
const FRAME_MS = 45;
const BLOCK_MS = 10 * 60 * 1000;

/** `text` with up to `flips` characters each flipped in one of their low six
 *  bits. Spaces, non-ASCII and any flip that would leave printable ASCII are
 *  skipped, so the line never shows a control or blank glyph. */
function mutate(text, flips) {
    const chars = [...text];
    for (let n = 0; n < flips; n++) {
        const i = Math.floor(Math.random() * chars.length);
        const code = chars[i].charCodeAt(0);
        const flipped = code ^ (1 << Math.floor(Math.random() * 6));
        if (code > 0x20 && code < 0x7f && flipped > 0x20 && flipped < 0x7f) {
            chars[i] = String.fromCharCode(flipped);
        }
    }
    return chars.join("");
}

function flickerOnArrival(row) {
    const title = row.querySelector(".ledger-title");
    const original = title.textContent;
    let timer = 0;
    const flicker = () => {
        if (timer) return;
        let frame = 0;
        timer = setInterval(() => {
            frame++;
            if (frame > FRAMES) {
                clearInterval(timer);
                timer = 0;
                title.textContent = original;
                return;
            }
            title.textContent = mutate(original, FRAMES - frame + 1);
        }, FRAME_MS);
    };
    row.addEventListener("mouseenter", flicker);
    title.addEventListener("focus", flicker);
}

/** "~4,100" style: tens under a thousand blocks, hundreds above. */
function roughly(blocks) {
    const unit = blocks < 1000 ? 10 : 100;
    return `~${(Math.round(blocks / unit) * unit).toLocaleString("en-US")}`;
}

function markBlocksAgo(rows) {
    const dated = rows
        .map((row) => ({
            block: row.querySelector(".ledger-block[data-height]"),
            day: row.querySelector(".ledger-date")?.getAttribute("datetime"),
        }))
        .filter(({ block, day }) => block && day);
    if (dated.length === 0) return;

    // Midday UTC of the post's day: the height is only known to the day.
    const time = (day) => Date.parse(`${day}T12:00:00Z`);
    const height = (block) => Number(block.dataset.height);
    const newest = dated.reduce((a, b) => (height(b.block) > height(a.block) ? b : a));
    const tip = height(newest.block) + (Date.now() - time(newest.day)) / BLOCK_MS;

    for (const { block } of dated) {
        const ago = tip - height(block);
        if (ago < 1) continue;
        const note = document.createElement("span");
        note.className = "ledger-ago";
        note.textContent = `${roughly(ago)} blocks ago`;
        block.append(note);
    }
}

// ---- Filter by tag ----

/** The tags as buttons: blog-gen writes them as text, so they read as plain
 *  labels where this script does not run. */
function tagButtons(rows) {
    for (const tag of rows.flatMap((row) => [...row.querySelectorAll(".ledger-tag")])) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = tag.className;
        button.dataset.tag = tag.dataset.tag;
        button.textContent = tag.textContent;
        button.setAttribute("aria-pressed", "false");
        tag.replaceWith(button);
    }
}

function filterBy(rows, tags, status) {
    const known = new Set(tags.map((t) => t.dataset.tag));

    const apply = (tag) => {
        const active = known.has(tag) ? tag : null;
        let shown = 0;
        for (const row of rows) {
            row.hidden = active !== null && !row.querySelector(`[data-tag="${CSS.escape(active)}"]`);
            if (!row.hidden) shown++;
        }
        for (const t of tags) t.setAttribute("aria-pressed", String(t.dataset.tag === active));

        status.hidden = active === null;
        if (active !== null) {
            const clear = document.createElement("button");
            clear.type = "button";
            clear.className = "ledger-filter-clear";
            clear.textContent = "x clear";
            clear.addEventListener("click", () => apply(null));
            status.replaceChildren(`showing ${active}: ${shown} of ${rows.length} `, clear);
        }

        const url = new URL(location.href);
        if (active === null) url.searchParams.delete("tag");
        else url.searchParams.set("tag", active);
        history.replaceState(null, "", url);
    };

    // A second click on the active tag clears it.
    for (const t of tags) {
        t.addEventListener("click", () => {
            apply(t.getAttribute("aria-pressed") === "true" ? null : t.dataset.tag);
        });
    }
    apply(new URLSearchParams(location.search).get("tag"));
}

const rows = [...document.querySelectorAll(".ledger-row")];
rows.forEach(flickerOnArrival);
markBlocksAgo(rows);

const list = document.querySelector(".ledger");
if (list) {
    tagButtons(rows);
    const status = document.createElement("p");
    status.className = "ledger-filter";
    status.setAttribute("role", "status");
    list.before(status);
    filterBy(rows, [...list.querySelectorAll(".ledger-tag")], status);
}
