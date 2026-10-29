// The live refresh: a fresh render of the current URL is fetched and swapped
// in. The browser work (fetch, DOM) comes in through RefreshIO, so the
// decision of whether the render may still be used is testable on its own.

export interface PageSource {
  ok: boolean;
  redirected: boolean;
  html: string;
}

export interface RefreshIO {
  // The current location, read before the fetch and again after it.
  url(): string;
  // Fetches the render; null when the server could not be reached.
  fetchPage(url: string): Promise<PageSource | null>;
  // Whether the live search field holds newer text than url's query.
  searchMismatch(url: string): boolean;
  // Puts the render in place; false when it lacks the page's parts.
  swap(html: string): boolean;
  reload(): void;
}

export type RefreshOutcome = "swapped" | "skipped" | "reloaded";

// refresh swaps in a fresh render of the current URL unless, by the time it
// arrives, it would throw something away: a newer URL or filter text, or,
// per `safe`, what the user started doing while the request was in flight
// (a ticked checkbox, a selection, an open menu). `safe` is the same test
// the caller made before fetching; it is asked again because the user had
// the whole round trip to act.
export async function refresh(io: RefreshIO, safe: () => boolean): Promise<RefreshOutcome> {
  const expectedURL = io.url();
  const page = await io.fetchPage(expectedURL);
  if (page === null) return "skipped"; // offline for a moment; the next poll tries again
  if (!page.ok || page.redirected) {
    io.reload();
    return "reloaded";
  }
  // A slower response must not replace a newer filter or typed text, nor
  // what the user selected or ticked meanwhile.
  if (io.url() !== expectedURL || io.searchMismatch(expectedURL) || !safe()) return "skipped";
  if (!io.swap(page.html)) {
    io.reload();
    return "reloaded";
  }
  return "swapped";
}
