#!/usr/bin/env node
/** Self-test the bounded resolver against a package that blocks package.json exports. */

import { strict as assert } from "node:assert";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";

import { loadExactPackageMetadata } from "./node_package_identity.mjs";

const root = await mkdtemp(join(tmpdir(), "phase3p-node-package-identity-"));
try {
  await writeFile(join(root, "package.json"), '{"name":"phase3p-fixture-root","private":true,"type":"module"}\n');
  const target = join(root, "node_modules", "@phase3p", "no-package-json-export");
  await mkdir(dirname(target), { recursive: true });
  const fixture = fileURLToPath(new URL("../tests/fixtures/node-package-identity/no-package-json-export/", import.meta.url));
  await cp(fixture, target, { recursive: true });

  const requireFromRoot = createRequire(join(root, "package.json"));
  assert.throws(
    () => requireFromRoot.resolve("@phase3p/no-package-json-export/package.json"),
    (error) => error?.code === "ERR_PACKAGE_PATH_NOT_EXPORTED",
  );
  const result = await loadExactPackageMetadata({
    dependencyRoot: root,
    packageName: "@phase3p/no-package-json-export",
    exportedSpecifier: "@phase3p/no-package-json-export",
    expectedVersion: "1.2.3",
  });
  assert.equal(result.packageJson.name, "@phase3p/no-package-json-export");
  assert.equal(result.packageJson.version, "1.2.3");
  assert.ok(result.entrypoint.endsWith("/index.js"));
  process.stdout.write("OK bounded package identity blocks package.json export\n");
} finally {
  await rm(root, { recursive: true, force: true });
}
