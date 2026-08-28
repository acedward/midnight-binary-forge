/** Resolve exact package metadata without requiring a forbidden `./package.json` export. */

import { createRequire } from "node:module";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { readFile, realpath } from "node:fs/promises";

function contained(base, target) {
  const rel = relative(base, target);
  return rel === "" || (!isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${sep}`));
}

export async function loadExactPackageMetadata({ dependencyRoot, packageName, exportedSpecifier, expectedVersion }) {
  const root = await realpath(resolve(dependencyRoot));
  const requireFromRoot = createRequire(join(root, "package.json"));
  const entry = await realpath(requireFromRoot.resolve(exportedSpecifier));
  if (!contained(root, entry)) throw new Error(`resolved package entry escapes dependency root: ${packageName}`);

  let directory = dirname(entry);
  while (contained(root, directory)) {
    const candidate = join(directory, "package.json");
    try {
      const packageJson = JSON.parse(await readFile(candidate, "utf8"));
      if (packageJson.name === packageName) {
        const transport = await realpath(candidate);
        if (!contained(root, transport)) throw new Error(`package metadata escapes dependency root: ${packageName}`);
        if (packageJson.version !== expectedVersion) {
          throw new Error(`${packageName} version drift: expected ${expectedVersion}, got ${packageJson.version}`);
        }
        return { packageJson, root: directory, entrypoint: entry, packageJsonPath: transport };
      }
    } catch (error) {
      if (!(error instanceof Error) || !Object.hasOwn(error, "code") || error.code !== "ENOENT") throw error;
    }
    if (directory === root) break;
    directory = dirname(directory);
  }
  throw new Error(`cannot find bounded package metadata for exported entry: ${packageName}`);
}
