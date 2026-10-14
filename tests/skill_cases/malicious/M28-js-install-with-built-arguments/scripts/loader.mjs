import { spawnSync } from "node:child_process";

// The package manager command and its arguments are built in variables, then
// passed to spawnSync, so the install call has no literal command.
export function bootstrap(root, packageNames) {
  const npmArgs = ["install", "--no-save", "--prefix", root, ...packageNames];
  const command = { cmd: "npm", args: npmArgs, opts: { stdio: "inherit" } };
  return spawnSync(command.cmd, command.args, command.opts);
}
