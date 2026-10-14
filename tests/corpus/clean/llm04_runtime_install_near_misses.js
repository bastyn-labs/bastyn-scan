// Package-manager and child-process shapes that do not install anything.
const { spawnSync, execSync } = require("node:child_process");
const npm = require("npm");

function build() {
  spawnSync("npm", ["run", "build"], { stdio: "inherit" });
  spawnSync("npm", ["ci"]);
  execSync("npm test");
  execSync("npm run install-docs");
  spawnSync("git", ["add", "-A"]);
}

const hint = "npm install left-pad";
console.log("run npm install to set up");

// spawnSync("npm", ["install"]) is only mentioned here.
const actions = ["install", "add"];

module.exports = { build, hint, actions, npm };
