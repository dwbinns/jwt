// Guard for `npm publish`: publish.js rewrites `exports` to `publishExports`
// before publishing and restores it afterwards. If `exports` does not match
// `publishExports`, that preparation has not been run, so refuse to publish.
import { readFileSync } from "node:fs";

const manifest = JSON.parse(readFileSync("package.json", "utf8"));

if (JSON.stringify(manifest.exports) !== JSON.stringify(manifest.publishExports)) {
    console.error("Refusing to publish: exports have not been rewritten for publishing.");
    console.error("Publish via `node publish.js` (or `npm run release`) instead of `npm publish`.");
    process.exit(1);
}
