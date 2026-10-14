// Code that installs packages as a child process while it runs.
const { spawnSync, execSync } = require("node:child_process");

function ensureHelper(name) {
  spawnSync("npm", ["install", "--no-save", name], { stdio: "inherit" });
}

function ensureFormatter() {
  execSync("pnpm add prettier");
}

module.exports = { ensureHelper, ensureFormatter };
