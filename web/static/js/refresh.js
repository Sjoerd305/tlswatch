// The live refresh: a fresh render of the current URL is fetched and swapped
// in. The browser work (fetch, DOM) comes in through RefreshIO, so the
// decision of whether the render may still be used is testable on its own.
// refresh swaps in a fresh render of the current URL unless, by the time it
// arrives, it would throw something away: a newer URL or filter text, or,
// per `safe`, what the user started doing while the request was in flight
// (a ticked checkbox, a selection, an open menu). `safe` is the same test
// the caller made before fetching; it is asked again because the user had
// the whole round trip to act.
export async function refresh(io, safe) {
    const expectedURL = io.url();
    const page = await io.fetchPage(expectedURL);
    if (page === null)
        return "skipped"; // offline for a moment; the next poll tries again
    if (!page.ok || page.redirected) {
        io.reload();
        return "reloaded";
    }
    // A slower response must not replace a newer filter or typed text, nor
    // what the user selected or ticked meanwhile.
    if (io.url() !== expectedURL || io.searchMismatch(expectedURL) || !safe())
        return "skipped";
    if (!io.swap(page.html)) {
        io.reload();
        return "reloaded";
    }
    return "swapped";
}
