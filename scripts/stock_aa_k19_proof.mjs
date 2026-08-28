#!/usr/bin/env node
/**
 * Generate and prove a deterministic, non-secret stock-AA execute call.
 *
 * The script is intentionally tied to the exact AA/midnight-js dependency line
 * used by the stock K19 Manager.  It never reads a wallet, node, indexer,
 * captured request, or environment secret.  All witness and transaction
 * randomness comes from the public seed below, and the inert native-owner
 * execute input comes from the AA simulator's public fixture.
 */

import { createHash } from "node:crypto";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createReadStream } from "node:fs";
import { readFile, stat } from "node:fs/promises";

import { loadExactPackageMetadata } from "./node_package_identity.mjs";

const PUBLIC_RNG_SEED = Buffer.from("midnight-binary-forge/phase3p/stock-aa-k19/v1", "utf8");
const EXPECTED_EXECUTE_BZKIR_SHA256 = "ab697f15c424d5c5d47c3dbfe114521611bcd28e3c9655d84d388b5f0f16a06b";
const EXPECTED_EXECUTE_BZKIR_SIZE = 184411;
const EXPECTED_EXECUTE_PROVER_SIZE = 1141041970;
const EXPECTED_EXECUTE_PROVER_SHA256 = "382ae4325f239a3e4e9ac292cacbb1ed1eceec71112eefa2f7557f6ecbe6865a";
const EXPECTED_PREIMAGE_BYTES = 707;
const EXPECTED_PREIMAGE_SHA256 = "1326dcdf0e667b33571ef2f622b7ed016a34ba93f203642fa3bc3aeca0d6aa26";
const EXPECTED_KEY_LOCATION = "contract:f814c7a87a346c4dfcd1ea8dc976046714f84c25e292156269822805b3a718be/execute?vk=e24ba5cf69bd494765b5daa79da9b6da55a5385e625b060467184b156035fd3b";
const EXPECTED_AA_COMMIT = "713a20215f33e02904ea5bd699b7de7f76562e1b";
const EXPECTED_AA_TREE = "b80be8377cf97913b9bfef0f3efe3870bdd56274";
const EXPECTED_PACKAGE_VERSIONS = Object.freeze({
  "@midnight-ntwrk/compact-runtime": "0.18.0-rc.1",
  "@midnight-ntwrk/midnight-js-contracts": "5.0.0-beta.6",
  "@midnight-ntwrk/midnight-js-http-client-proof-provider": "5.0.0-beta.6",
  "@midnight-ntwrk/midnight-js-network-id": "5.0.0-beta.6",
  "@midnight-ntwrk/midnight-js-node-zk-config-provider": "5.0.0-beta.6",
  "@midnight-ntwrk/midnight-js-protocol": "5.0.0-beta.6",
  "@midnightntwrk/ledger-v9": "1.0.0-rc.3",
  "@noble/curves": "2.2.0",
});
const EXPORTED_PACKAGE_ENTRYPOINTS = Object.freeze({
  "@midnight-ntwrk/compact-runtime": "@midnight-ntwrk/compact-runtime",
  "@midnight-ntwrk/midnight-js-contracts": "@midnight-ntwrk/midnight-js-contracts",
  "@midnight-ntwrk/midnight-js-http-client-proof-provider": "@midnight-ntwrk/midnight-js-http-client-proof-provider",
  "@midnight-ntwrk/midnight-js-network-id": "@midnight-ntwrk/midnight-js-network-id",
  "@midnight-ntwrk/midnight-js-node-zk-config-provider": "@midnight-ntwrk/midnight-js-node-zk-config-provider",
  "@midnight-ntwrk/midnight-js-protocol": "@midnight-ntwrk/midnight-js-protocol/compact-js",
  "@midnightntwrk/ledger-v9": "@midnightntwrk/ledger-v9",
  "@noble/curves": "@noble/curves/secp256k1.js",
});

function fail(message) {
  throw new Error(message);
}

function parseArgs(argv) {
  const values = {
    dependencyRoot: undefined,
    artifactRoot: undefined,
    contractModule: undefined,
    proofServer: undefined,
    expectedAaCommit: EXPECTED_AA_COMMIT,
    expectedAaTree: EXPECTED_AA_TREE,
    output: undefined,
    preflightOnly: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    if (name === "--preflight-only") {
      values.preflightOnly = true;
      continue;
    }
    const key = {
      "--dependency-root": "dependencyRoot",
      "--artifact-root": "artifactRoot",
      "--contract-module": "contractModule",
      "--proof-server": "proofServer",
      "--expected-aa-commit": "expectedAaCommit",
      "--expected-aa-tree": "expectedAaTree",
      "--output": "output",
    }[name];
    if (key === undefined || argv[index + 1] === undefined) fail(`invalid argument: ${name}`);
    values[key] = argv[index + 1];
    index += 1;
  }
  for (const required of ["dependencyRoot", "artifactRoot", "contractModule"]) {
    if (values[required] === undefined) fail(`missing --${required.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`);
  }
  if (!values.preflightOnly && values.proofServer === undefined) fail("missing --proof-server");
  return values;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function installDeterministicCrypto() {
  let counter = 0n;
  const original = globalThis.crypto;
  const deterministic = Object.create(original);
  Object.defineProperty(deterministic, "getRandomValues", {
    configurable: false,
    enumerable: true,
    value(target) {
      if (!ArrayBuffer.isView(target) || target instanceof DataView) {
        throw new TypeError("getRandomValues target must be an integer TypedArray");
      }
      const bytes = new Uint8Array(target.buffer, target.byteOffset, target.byteLength);
      let offset = 0;
      while (offset < bytes.length) {
        const count = Buffer.alloc(8);
        count.writeBigUInt64BE(counter);
        counter += 1n;
        const block = createHash("sha256").update(PUBLIC_RNG_SEED).update(count).digest();
        offset += block.copy(bytes, offset, 0, Math.min(block.length, bytes.length - offset));
      }
      return target;
    },
  });
  Object.defineProperty(globalThis, "crypto", { configurable: true, value: deterministic });
  return () => {
    counter = 0n;
  };
}

async function sha256File(path) {
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return digest.digest("hex");
}

async function loadPinnedModules(dependencyRoot) {
  const packageInfo = new Map();
  const observed = {};
  for (const [packageName, expected] of Object.entries(EXPECTED_PACKAGE_VERSIONS)) {
    const info = await loadExactPackageMetadata({
      dependencyRoot,
      packageName,
      exportedSpecifier: EXPORTED_PACKAGE_ENTRYPOINTS[packageName],
      expectedVersion: expected,
    });
    packageInfo.set(packageName, info);
    observed[packageName] = info.packageJson.version;
  }
  const protocolPackage = packageInfo.get("@midnight-ntwrk/midnight-js-protocol")?.packageJson;
  if (protocolPackage?.dependencies?.["@midnight-ntwrk/compact-js"] !== "2.5.5-rc.7") {
    fail("@midnight-ntwrk/compact-js transitive pin drift");
  }
  observed["@midnight-ntwrk/compact-js"] = "2.5.5-rc.7";
  const dynamic = async (specifier) => {
    const packageName = specifier.startsWith("@") ? specifier.split("/").slice(0, 2).join("/") : specifier.split("/")[0];
    const info = packageInfo.get(packageName);
    if (info === undefined) fail(`unversioned dependency import: ${specifier}`);
    const suffix = specifier.slice(packageName.length);
    const exportKey = suffix === "" ? "." : `.${suffix}`;
    let selected = info.packageJson.exports?.[exportKey];
    if (selected !== undefined && typeof selected === "object") {
      selected = selected.import ?? selected.default;
    }
    if (selected === undefined && suffix === "") selected = info.packageJson.module ?? info.packageJson.main;
    if (typeof selected !== "string") fail(`cannot resolve ESM export ${specifier}`);
    return import(pathToFileURL(resolve(info.root, selected)).href);
  };
  return {
    observed,
    compactJs: await dynamic("@midnight-ntwrk/midnight-js-protocol/compact-js"),
    compactRuntime: await dynamic("@midnight-ntwrk/compact-runtime"),
    contracts: await dynamic("@midnight-ntwrk/midnight-js-contracts"),
    proofClient: await dynamic("@midnight-ntwrk/midnight-js-http-client-proof-provider"),
    networkId: await dynamic("@midnight-ntwrk/midnight-js-network-id"),
    zkConfig: await dynamic("@midnight-ntwrk/midnight-js-node-zk-config-provider"),
    ledger: await dynamic("@midnight-ntwrk/midnight-js-protocol/ledger"),
    secp: await dynamic("@noble/curves/secp256k1.js"),
  };
}

function publicBytes(label) {
  const encoded = Buffer.from(label, "utf8");
  if (encoded.length > 32) fail(`public label is longer than 32 bytes: ${label}`);
  const result = new Uint8Array(32);
  result.set(encoded);
  return result;
}

function defaultExecutePayload() {
  const zero32 = () => new Uint8Array(32);
  return {
    selector: 0n,
    authMode: 0n,
    account: zero32(),
    owner: new Uint8Array(20),
    accountSalt: zero32(),
    nonce: 0n,
    validUntil: 0n,
    primaryColor: zero32(),
    primaryAmount: 0n,
    recipientKind: 0n,
    recipient: zero32(),
    toAccount: zero32(),
    wantNonce: zero32(),
    wantColor: zero32(),
    wantAmount: 0n,
    creditAccount: zero32(),
  };
}

function inertSignatureAndPoint(secp256k1) {
  const publicKey = secp256k1.getPublicKey(
    Buffer.from("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318", "hex"),
    false,
  );
  return {
    signature: {
      r: 0x18c8c0b1a03a9d14923824f037423de763035cc9b4ae011b10519473553845fan,
      s: 0x4b23d69e009b1b012a044d2651134524419f420f6157d333eda0b3cb2d469f81n,
    },
    point: {
      x: BigInt(`0x${Buffer.from(publicKey.subarray(1, 33)).toString("hex")}`),
      y: BigInt(`0x${Buffer.from(publicKey.subarray(33, 65)).toString("hex")}`),
      identity: false,
    },
  };
}

async function assertArtifactIdentity(artifactRoot, preflightOnly) {
  const bzkir = await readFile(join(artifactRoot, "zkir", "execute.bzkir"));
  if (bzkir.length !== EXPECTED_EXECUTE_BZKIR_SIZE || sha256(bzkir) !== EXPECTED_EXECUTE_BZKIR_SHA256) {
    fail("stock AA execute.bzkir identity drift");
  }
  const result = { bzkirBytes: bzkir.length, bzkirSha256: sha256(bzkir) };
  if (!preflightOnly) {
    const proverPath = join(artifactRoot, "keys", "execute.prover");
    const proverSize = (await stat(proverPath)).size;
    if (proverSize !== EXPECTED_EXECUTE_PROVER_SIZE) fail(`stock AA execute.prover size drift: ${proverSize}`);
    const proverDigest = await sha256File(proverPath);
    if (proverDigest !== EXPECTED_EXECUTE_PROVER_SHA256) fail(`stock AA execute.prover digest drift: ${proverDigest}`);
    result.proverBytes = proverSize;
    result.proverSha256 = proverDigest;
  }
  return result;
}

async function createStockCall(modules, managerModule, artifactRoot) {
  const ownerSecret = publicBytes("phase3p-public-k19");
  const witnesses = {
    localOwnerSecret: ({ privateState }) => [privateState, ownerSecret],
  };
  const compiledContract = modules.compactJs.CompiledContract.make("contract-manager", managerModule.Contract).pipe(
    modules.compactJs.CompiledContract.withWitnesses(witnesses),
    modules.compactJs.CompiledContract.withCompiledFileAssets(artifactRoot),
  );
  const zkConfigProvider = new modules.zkConfig.NodeZkConfigProvider(artifactRoot);
  const coinPublicKey = modules.ledger.sampleCoinPublicKey();
  const encryptionPublicKey = modules.ledger.sampleEncryptionPublicKey();
  const deploy = await modules.contracts.createUnprovenDeployTxFromVerifierKeys(
    zkConfigProvider,
    coinPublicKey,
    {
      compiledContract,
      signingKey: modules.compactRuntime.sampleSigningKey(),
      initialPrivateState: {},
      args: [new Uint8Array(32).fill(0xdd)],
    },
    encryptionPublicKey,
  );
  const { signature, point } = inertSignatureAndPoint(modules.secp.secp256k1);
  const call = await modules.contracts.createUnprovenCallTxFromInitialStates(
    zkConfigProvider,
    {
      compiledContract,
      circuitId: "execute",
      contractAddress: deploy.public.contractAddress,
      args: [defaultExecutePayload(), signature, point],
      coinPublicKey,
      initialContractState: deploy.public.initialContractState,
      initialZswapChainState: new modules.ledger.ZswapChainState(),
      ledgerParameters: modules.ledger.LedgerParameters.initialParameters(),
      initialPrivateState: {},
    },
    encryptionPublicKey,
  );
  return { call, zkConfigProvider };
}

function tracingProvider(base, trace, abortAfterCheck) {
  return {
    async check(serializedPreimage, keyLocation) {
      trace.push({
        operation: "check",
        keyLocation,
        preimageBytes: serializedPreimage.length,
        preimageSha256: sha256(serializedPreimage),
      });
      if (abortAfterCheck) throw new Error("PHASE3P_DETERMINISM_CAPTURE_COMPLETE");
      return base.check(serializedPreimage, keyLocation);
    },
    async prove(serializedPreimage, keyLocation, overwriteBindingInput) {
      trace.push({
        operation: "prove",
        keyLocation,
        overwriteBindingInput: overwriteBindingInput?.toString(),
        preimageBytes: serializedPreimage.length,
        preimageSha256: sha256(serializedPreimage),
      });
      return base.prove(serializedPreimage, keyLocation, overwriteBindingInput);
    },
    lookupKey: (keyLocation) => base.lookupKey(keyLocation),
  };
}

async function capturePreimage(modules, callData) {
  const trace = [];
  const provider = tracingProvider({
    check: async () => fail("capture check must abort before delegation"),
    prove: async () => fail("capture prove must not run"),
    lookupKey: async () => undefined,
  }, trace, true);
  try {
    await callData.private.unprovenTx.prove(provider, modules.ledger.CostModel.initialCostModel());
    fail("determinism capture unexpectedly completed a proof");
  } catch (error) {
    if (!(error instanceof Error) || !error.message.includes("PHASE3P_DETERMINISM_CAPTURE_COMPLETE")) throw error;
  }
  if (trace.length !== 1 || trace[0].operation !== "check") fail("expected one captured execute proof preimage");
  return trace[0];
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const resetRng = installDeterministicCrypto();
  const modules = await loadPinnedModules(args.dependencyRoot);
  modules.networkId.setNetworkId("undeployed");
  const managerModule = await import(pathToFileURL(resolve(args.contractModule)).href);
  const artifactIdentity = await assertArtifactIdentity(resolve(args.artifactRoot), args.preflightOnly);

  resetRng();
  const first = await createStockCall(modules, managerModule, resolve(args.artifactRoot));
  const firstCapture = await capturePreimage(modules, first.call);
  resetRng();
  const second = await createStockCall(modules, managerModule, resolve(args.artifactRoot));
  const secondCapture = await capturePreimage(modules, second.call);
  if (JSON.stringify(firstCapture) !== JSON.stringify(secondCapture)) fail("stock AA proof preimage is not deterministic");
  if (
    firstCapture.preimageBytes !== EXPECTED_PREIMAGE_BYTES ||
    firstCapture.preimageSha256 !== EXPECTED_PREIMAGE_SHA256 ||
    firstCapture.keyLocation !== EXPECTED_KEY_LOCATION
  ) {
    fail(`stock AA deterministic preimage identity drift: ${JSON.stringify(firstCapture)}`);
  }

  const evidence = {
    schemaVersion: "stock-aa-k19-proof-v1",
    aa: { commit: args.expectedAaCommit, tree: args.expectedAaTree },
    dependencies: modules.observed,
    circuit: { id: "execute", k: 19, ...artifactIdentity },
    generator: {
      publicSeedSha256: sha256(PUBLIC_RNG_SEED),
      publicWitnessLabel: "phase3p-public-k19",
      capturedRequest: false,
      deterministicPreimage: firstCapture,
    },
    proof: { executed: false },
  };

  if (!args.preflightOnly) {
    resetRng();
    const real = await createStockCall(modules, managerModule, resolve(args.artifactRoot));
    const base = modules.proofClient.httpClientProvingProvider(args.proofServer, real.zkConfigProvider, { timeout: 900000 });
    const trace = [];
    const started = Date.now();
    const proven = await real.call.private.unprovenTx.prove(
      tracingProvider(base, trace, false),
      modules.ledger.CostModel.initialCostModel(),
    );
    const serialized = proven.serialize();
    if (trace.length !== 2 || trace[0].operation !== "check" || trace[1].operation !== "prove") {
      fail(`unexpected real proof trace: ${JSON.stringify(trace)}`);
    }
    if (trace[0].preimageSha256 !== firstCapture.preimageSha256 || trace[1].preimageSha256 !== firstCapture.preimageSha256) {
      fail("real proof did not use the deterministic preimage");
    }
    evidence.proof = {
      executed: true,
      endpoint: "/prove",
      elapsedMs: Date.now() - started,
      resultBytes: serialized.length,
      resultSha256: sha256(serialized),
      trace,
    };
  }

  const rendered = `${JSON.stringify(evidence, null, 2)}\n`;
  if (args.output !== undefined) {
    const { writeFile } = await import("node:fs/promises");
    await writeFile(resolve(args.output), rendered, { encoding: "utf8", mode: 0o644 });
  }
  process.stdout.write(rendered);
}

await main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
});
