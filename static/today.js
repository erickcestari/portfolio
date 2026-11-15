// The date behind the date-based touches: the moon's phase, December snow
// and Bitcoin's anniversaries. `?sky-date=2026-12-24` in the URL pretends it
// is that day, so a season can be checked out of season.

/** Now, or noon of the `sky-date` in the URL when it holds a valid date. */
export function now() {
    const preview = new URLSearchParams(location.search).get("sky-date");
    if (preview && /^\d{4}-\d{2}-\d{2}$/.test(preview)) {
        const day = new Date(`${preview}T12:00:00`);
        if (!Number.isNaN(day.getTime())) return day;
    }
    return new Date();
}

// Bitcoin's birthdays: the whitepaper (2008-10-31) and the genesis block
// (2009-01-03), by month and day.
const BITCOIN_DAYS = { "10-31": "whitepaper", "01-03": "genesis" };

/** Which Bitcoin anniversary `date` falls on, if any. */
export function bitcoinDay(date) {
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const day = String(date.getDate()).padStart(2, "0");
    return BITCOIN_DAYS[`${month}-${day}`] ?? null;
}
