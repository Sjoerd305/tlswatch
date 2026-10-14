// Shared helpers for the page modules: DOM lookup, ready hook, and the JSON
// API client that carries the CSRF token.

export function $<E extends Element = HTMLElement>(selector: string, root: ParentNode = document): E | null {
  return root.querySelector<E>(selector);
}

export function $$<E extends Element = HTMLElement>(selector: string, root: ParentNode = document): E[] {
  return Array.from(root.querySelectorAll<E>(selector));
}

export function onReady(fn: () => void): void {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", fn, { once: true });
  } else {
    fn();
  }
}

// English error messages, one place for every text the scripts show.
export const messages = {
  network: "The server could not be reached. Check your connection and try again.",
  csrf: "Your session has expired. Reload the page and try again.",
  unauthorized: "You are signed out. Sign in again to continue.",
  forbidden: "You do not have permission for this action.",
  notFound: "This item no longer exists.",
  server: "Something went wrong on the server. Try again; the log has details.",
  unknown: "The request failed.",
  copied: "copied",
  copyFailed: "copy failed",
} as const;

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export function csrfToken(): string {
  return $<HTMLMetaElement>('meta[name="csrf-token"]')?.content ?? "";
}

function messageForStatus(status: number): string {
  switch (status) {
    case 401:
      return messages.unauthorized;
    case 403:
      return messages.forbidden;
    case 404:
      return messages.notFound;
    case 419:
      return messages.csrf;
    default:
      return status >= 500 ? messages.server : messages.unknown;
  }
}

export async function api<T>(method: string, url: string, body?: FormData | object): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    "X-CSRF-Token": csrfToken(),
  };
  const init: RequestInit = { method, headers, credentials: "same-origin" };
  if (body instanceof FormData) {
    init.body = body;
  } else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }

  let res: Response;
  try {
    res = await fetch(url, init);
  } catch {
    throw new ApiError(0, messages.network);
  }

  const type = res.headers.get("Content-Type") ?? "";
  let data: unknown = null;
  if (type.includes("application/json")) {
    try {
      data = await res.json();
    } catch {
      data = null;
    }
  }

  if (!res.ok) {
    const err = data !== null && typeof data === "object" && "error" in data ? (data as { error: unknown }).error : null;
    throw new ApiError(res.status, typeof err === "string" && err !== "" ? err : messageForStatus(res.status));
  }
  return data as T;
}
