// Publishes the package with the exports map rewritten so npm consumers get
// the built JS by default, while the workspace keeps TypeScript source as the
// default. The original package.json is restored afterwards.
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const original = readFileSync("package.json", "utf8");
const manifest = JSON.parse(original);

manifest.exports = manifest.publishExports;

writeFileSync("package.json", JSON.stringify(manifest, null, 4) + "\n");

try {
    const result = spawnSync("npm", ["publish", ...process.argv.slice(2)], { stdio: "inherit" });
    process.exitCode = result.status ?? 1;
} finally {
    writeFileSync("package.json", original);
}
