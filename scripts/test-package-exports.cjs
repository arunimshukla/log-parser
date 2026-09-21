const { pathToFileURL } = require("node:url");
const { resolve } = require("node:path");

async function main() {
  const esm = await import(pathToFileURL(resolve("lib/esm/index.js")).href);
  const cjs = require(resolve("lib/cjs/index.js"));

  for (const [format, exports] of [["ESM", esm], ["CommonJS", cjs]]) {
    if (typeof exports.processLogs !== "function") {
      throw new Error(`${format} entry point did not export processLogs`);
    }
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
