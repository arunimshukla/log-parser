const { mkdirSync, writeFileSync } = require("node:fs");

for (const [directory, type] of [
  ["lib/esm", "module"],
  ["lib/cjs", "commonjs"],
]) {
  mkdirSync(directory, { recursive: true });
  writeFileSync(`${directory}/package.json`, `${JSON.stringify({ type })}\n`);
}
