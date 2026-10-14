// Fails when the npm tree holds anything besides the TypeScript compiler.
// The frontend has no runtime dependencies by design (see docs/specification.md).
import { readFileSync } from "node:fs";

const allowed = new Set(["typescript"]);
const problems = [];

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
for (const field of ["dependencies", "peerDependencies", "optionalDependencies", "bundledDependencies", "bundleDependencies"]) {
  const deps = pkg[field];
  if (deps && Object.keys(deps).length > 0) problems.push(`package.json: "${field}" must be empty`);
}
for (const name of Object.keys(pkg.devDependencies ?? {})) {
  if (!allowed.has(name)) problems.push(`package.json: devDependency "${name}" is not allowed`);
}

let lock;
try {
  lock = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"));
} catch {
  problems.push("package-lock.json is missing or unreadable");
}
if (lock) {
  for (const path of Object.keys(lock.packages ?? {})) {
    if (path === "") continue;
    const name = path.replace(/^.*node_modules\//, "");
    // TypeScript 7 ships its native compiler as per-platform optional packages.
    const platformBinary = /^@typescript\/typescript-[a-z0-9]+-[a-z0-9]+$/.test(name);
    if (!allowed.has(name) && !platformBinary) {
      problems.push(`package-lock.json: package "${name}" is not allowed`);
    }
  }
}

if (problems.length > 0) {
  console.error("check-deps failed:\n  " + problems.join("\n  "));
  process.exit(1);
}
console.log("check-deps: ok (typescript only)");
