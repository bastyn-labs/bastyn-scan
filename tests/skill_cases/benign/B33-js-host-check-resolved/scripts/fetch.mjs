import { isIP } from "node:net";
import { lookup } from "node:dns/promises";

// The hostname is resolved first and every returned address is checked.
function isPublicAddress(addr) {
  return !addr.startsWith("10.") && !addr.startsWith("127.");
}

export async function isPublicUrl(value) {
  const host = new URL(value).hostname;
  if (host === "localhost") return false;
  if (isIP(host)) return isPublicAddress(host);
  const found = await lookup(host, { all: true });
  return found.every((entry) => isPublicAddress(entry.address));
}

export async function download(value) {
  if (!(await isPublicUrl(value))) throw new Error("blocked");
  return fetch(value);
}
