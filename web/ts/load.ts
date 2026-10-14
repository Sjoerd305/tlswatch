// Lazy fragments: an element with data-load-url is filled from the JSON API
// ({ html }) the first time it is shown, e.g. a certificate's chain when its
// row is expanded.

// Loadable is the part of an element loadInto uses, so it can be tested
// without a DOM.
export interface Loadable {
  dataset: DOMStringMap;
  innerHTML: string;
  textContent: string | null;
  classList: { remove(...tokens: string[]): void };
}

export type FetchHTML = (url: string) => Promise<{ html?: string }>;

export const loadFailed = "could not be loaded";

// loadInto fills el from its data-load-url, once. On failure it shows a
// short note and keeps the URL, so expanding the row again retries.
export async function loadInto(el: Loadable, fetchHTML: FetchHTML): Promise<void> {
  const url = el.dataset["loadUrl"];
  if (url === undefined) return;
  delete el.dataset["loadUrl"];
  try {
    const reply = await fetchHTML(url);
    el.innerHTML = reply.html ?? "";
    el.classList.remove("muted");
  } catch {
    el.textContent = loadFailed;
    el.dataset["loadUrl"] = url;
  }
}
