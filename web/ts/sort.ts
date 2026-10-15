// Column sorting of rendered rows. The server renders the order the URL asks
// for (?sort=key&dir=desc, see internal/web/sort.go); a click on a column
// head re-orders the rows here the same way and puts the choice in the URL,
// so a reload or a live refresh keeps it. Every list has a default column
// whose ascending order is the list's own; that order carries no parameters.

export interface SortState {
  key: string;
  desc: boolean;
}

// compareValues orders two cell values as the server does: numbers by
// value, texts by their lowercased form, a missing value (null) last
// whichever the direction.
export function compareValues(a: string | null, b: string | null, num: boolean, desc: boolean): number {
  if (a === null || b === null) {
    if (a === b) return 0;
    return a === null ? 1 : -1;
  }
  let c: number;
  if (num) {
    const x = Number(a);
    const y = Number(b);
    c = x < y ? -1 : x > y ? 1 : 0;
  } else {
    const x = a.toLowerCase();
    const y = b.toLowerCase();
    c = x < y ? -1 : x > y ? 1 : 0;
  }
  return desc ? -c : c;
}

// order returns the positions of values in sorted order; equal values keep
// their relative order, so the list's own order breaks ties.
export function order(values: Array<string | null>, num: boolean, desc: boolean): number[] {
  const idx = values.map((_, i) => i);
  idx.sort((i, j) => compareValues(values[i] ?? null, values[j] ?? null, num, desc) || i - j);
  return idx;
}

// nextSort is the state after a click on key: the active column flips its
// direction, another column starts ascending.
export function nextSort(current: SortState, key: string): SortState {
  return { key, desc: key === current.key && !current.desc };
}

// setSortParams writes the state into a URL's parameters; the default
// order (def ascending) carries none.
export function setSortParams(params: URLSearchParams, s: SortState, def: string): void {
  params.delete("sort");
  params.delete("dir");
  if (s.key !== def || s.desc) params.set("sort", s.key);
  if (s.desc) params.set("dir", "desc");
}
