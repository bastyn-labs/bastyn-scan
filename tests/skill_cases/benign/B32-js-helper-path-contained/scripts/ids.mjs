import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve, sep } from "node:path";

// ext comes from the caller; the resolved path must stay inside the media directory.
export function reserve(projectDir, kind, ext) {
  const root = resolve(projectDir, ".media");
  mkdirSync(root, { recursive: true });
  const target = resolve(join(root, `${kind}_001${ext}`));
  if (!target.startsWith(root + sep)) throw new Error("outside media directory");
  writeFileSync(target, "");
  return target;
}
