import path from "node:path";

const allowedExtensions = new Set([".css", ".html", ".ico", ".js", ".json", ".map", ".png", ".svg", ".txt", ".woff2"]);

export function isAppProtocolUrl(rawUrl: string): boolean {
  try {
    return new URL(rawUrl).protocol === "app:";
  } catch {
    return false;
  }
}

export function resolveAppProtocolPath(rawUrl: string, assetRoot: string): string {
  if (rawUrl.includes("..") || rawUrl.toLowerCase().includes("%2e")) {
    throw new Error("Renderer asset path cannot contain traversal segments");
  }

  const url = new URL(rawUrl);

  if (url.protocol !== "app:") {
    throw new Error("Only app:// URLs are served by the renderer protocol");
  }

  const relativePath = normalizeAppPath(url);
  const extension = path.extname(relativePath);

  if (!allowedExtensions.has(extension)) {
    throw new Error("Renderer asset extension is not allowed");
  }

  const resolvedPath = path.resolve(assetRoot, `.${relativePath}`);
  const relativeToRoot = path.relative(assetRoot, resolvedPath);

  if (relativeToRoot.startsWith("..") || path.isAbsolute(relativeToRoot)) {
    throw new Error("Renderer asset path escapes the bundled asset root");
  }

  return resolvedPath;
}

function normalizeAppPath(url: URL): string {
  if (url.hostname === "index.html" && (url.pathname === "" || url.pathname === "/")) {
    return "/index.html";
  }

  if (url.hostname === "assets") {
    return `/assets${url.pathname}`;
  }

  if (url.hostname === "" && url.pathname.startsWith("/assets/")) {
    return url.pathname;
  }

  if (url.hostname === "index.html" && url.pathname.startsWith("/assets/")) {
    return url.pathname;
  }

  if (url.hostname === "" && url.pathname === "/index.html") {
    return "/index.html";
  }

  throw new Error("Renderer protocol request is outside the bundled app surface");
}
