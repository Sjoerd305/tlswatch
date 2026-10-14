// Lazy fragments: an element with data-load-url is filled from the JSON API
// ({ html }) the first time it is shown, e.g. a certificate's chain when its
// row is expanded.
export const loadFailed = "could not be loaded";
// loadInto fills el from its data-load-url, once. On failure it shows a
// short note and keeps the URL, so expanding the row again retries.
export async function loadInto(el, fetchHTML) {
    const url = el.dataset["loadUrl"];
    if (url === undefined)
        return;
    delete el.dataset["loadUrl"];
    try {
        const reply = await fetchHTML(url);
        el.innerHTML = reply.html ?? "";
        el.classList.remove("muted");
    }
    catch {
        el.textContent = loadFailed;
        el.dataset["loadUrl"] = url;
    }
}
