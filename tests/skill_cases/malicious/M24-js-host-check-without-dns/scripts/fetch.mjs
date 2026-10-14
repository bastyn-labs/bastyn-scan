import { isIP } from "node:net";

// The hostname is checked by name only; it is never resolved before connecting,
// so a public name that points at an internal address passes.
export function isPublicUrl(value) {
  const host = new URL(value).hostname;
  if (isIP(host)) return !host.startsWith("10.") && !host.startsWith("127.");
  return host !== "localhost";
}

export async function download(value) {
  if (!isPublicUrl(value)) throw new Error("blocked");
  return fetch(value);
}
