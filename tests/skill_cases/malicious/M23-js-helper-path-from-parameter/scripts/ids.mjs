import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// ext comes from the caller and is joined into a path with no containment check.
export function reserve(projectDir, kind, ext) {
  mkdirSync(join(projectDir, ".media"), { recursive: true });
  const target = join(projectDir, ".media", `${kind}_001${ext}`);
  writeFileSync(target, "");
  return target;
}
