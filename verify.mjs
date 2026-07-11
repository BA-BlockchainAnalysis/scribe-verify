#!/usr/bin/env node
// SPDX-License-Identifier: MIT
//
// scribe-verify — trustless verifier for BAScribe documents.
//
// Verifies that a signed PDF is anchored on-chain WITHOUT trusting BAScribe:
//   1. SHA-256 of the file == the Merkle leaf in the proof packet.
//   2. Folding the leaf with the Merkle proof (keccak256 over sorted 32-byte
//      pairs) reproduces the batch Merkle root.
//   3. The Stamper contract on Polygon has a non-zero timestamps(root) — the
//      value is the Unix block time the root was anchored.
//   4. (Optional) the Bitcoin OpenTimestamps proof, via the `ots` CLI.
//
// Nothing here trusts BAScribe: the proof, the contract and the chain are all
// public. The only network call is a read-only eth_call to a public Polygon RPC.
//
// Usage:
//   node verify.mjs <file.pdf>                 # fetch the packet by hash from bascribe.com
//   node verify.mjs <file.pdf> <packet.json>   # use a local packet you already downloaded
//   node verify.mjs --packet <packet.json>     # verify Merkle+chain without the file (skips step 1)
//
// The Merkle scheme matches BAScribe's src/lib/merkle.ts exactly:
//   SHA-256 leaves -> merkletreejs with keccak256 hashFn and sortPairs:true.

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import jsSha3 from "js-sha3";
const { keccak256 } = jsSha3;

// Public, keyless Polygon RPCs, tried in order. Override with POLYGON_RPC_URL.
const POLYGON_RPCS = process.env.POLYGON_RPC_URL
  ? [process.env.POLYGON_RPC_URL]
  : ["https://polygon-bor-rpc.publicnode.com", "https://polygon.drpc.org", "https://1rpc.io/matic"];
const AMOY_RPCS = process.env.POLYGON_AMOY_RPC_URL
  ? [process.env.POLYGON_AMOY_RPC_URL]
  : ["https://polygon-amoy-bor-rpc.publicnode.com", "https://rpc-amoy.polygon.technology"];

const green = (s) => `\x1b[32m${s}\x1b[0m`;
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;

function die(msg) {
  console.error(red("✗ " + msg));
  process.exit(1);
}

function sha256Hex(buf) {
  return "0x" + createHash("sha256").update(buf).digest("hex");
}

// keccak256 over the concatenation of two 32-byte buffers, sorted — the exact
// behaviour of merkletreejs { sortPairs: true }.
function hashPair(a, b) {
  const [x, y] = Buffer.compare(a, b) <= 0 ? [a, b] : [b, a];
  return Buffer.from(keccak256(Buffer.concat([x, y])), "hex");
}

function foldProof(leafHex, proofHexes) {
  let node = Buffer.from(leafHex.slice(2), "hex");
  for (const sib of proofHexes) {
    node = hashPair(node, Buffer.from(sib.slice(2), "hex"));
  }
  return "0x" + node.toString("hex");
}

// eth_call timestamps(bytes32) -> uint256, hand-encoded (no web3 dependency).
// Tries each RPC in the list until one answers; returns 0n if not anchored.
async function queryTimestamps(rpcs, contract, root) {
  const selector = keccak256("timestamps(bytes32)").slice(0, 8);
  const data = "0x" + selector + root.slice(2);
  const errors = [];
  for (const rpc of rpcs) {
    try {
      const res = await fetch(rpc, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to: contract, data }, "latest"] }),
      });
      const j = await res.json();
      if (j.error) throw new Error(j.error.message);
      if (typeof j.result !== "string" || !j.result.startsWith("0x") || j.result === "0x") {
        throw new Error(`unexpected result: ${JSON.stringify(j.result)}`);
      }
      return BigInt(j.result); // 0 = not anchored; otherwise the unix block time
    } catch (e) {
      errors.push(`${rpc}: ${e.message}`);
    }
  }
  throw new Error(`all Polygon RPCs failed:\n  ${errors.join("\n  ")}`);
}

async function loadPacket(pathOrHash) {
  if (/^0x[0-9a-f]{64}$/i.test(pathOrHash)) {
    const r = await fetch(`https://bascribe.com/api/verify/${pathOrHash.toLowerCase()}/packet`);
    if (!r.ok) die(`could not fetch packet for ${pathOrHash} (HTTP ${r.status})`);
    return r.json();
  }
  return JSON.parse(await readFile(pathOrHash, "utf8"));
}

async function main() {
  const args = process.argv.slice(2);
  let filePath = null;
  let packetArg = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--packet") packetArg = args[++i];
    else if (!filePath) filePath = args[i];
    else packetArg = args[i];
  }
  if (!filePath && !packetArg) {
    console.log("Usage: node verify.mjs <file.pdf | 0x-hash> [packet.json]");
    process.exit(2);
  }

  // A bare 0x-hash means "fetch and verify that document's packet" (no file
  // supplied, so the file-integrity step is skipped).
  if (filePath && /^0x[0-9a-f]{64}$/i.test(filePath)) {
    packetArg = filePath;
    filePath = null;
  }

  // Determine the leaf hash from the file (preferred) or the packet.
  let leaf = null;
  if (filePath && !filePath.startsWith("--")) {
    const buf = await readFile(filePath).catch(() => die(`cannot read file: ${filePath}`));
    leaf = sha256Hex(buf);
    console.log(`file SHA-256   ${dim(leaf)}`);
  }

  const packet = await loadPacket(packetArg || leaf);
  if (!packet?.merkle?.root || !packet?.polygon?.stamperContract) die("packet missing merkle/polygon fields");

  // Step 1 — file hash matches the packet leaf.
  if (leaf) {
    if (leaf.toLowerCase() !== String(packet.documentHash).toLowerCase()) {
      die(`file hash ${leaf} does not match packet documentHash ${packet.documentHash}`);
    }
    console.log(green("✓") + " step 1  file SHA-256 matches the anchored leaf");
  } else {
    leaf = packet.documentHash;
    console.log(dim("· step 1  skipped (no file supplied) — verifying packet only"));
  }

  // Step 2 — Merkle proof folds to the root.
  const computedRoot = foldProof(leaf, packet.merkle.proof || []);
  if (computedRoot.toLowerCase() !== String(packet.merkle.root).toLowerCase()) {
    die(`Merkle proof folds to ${computedRoot}, not the packet root ${packet.merkle.root}`);
  }
  console.log(green("✓") + " step 2  Merkle proof reproduces the batch root");

  // Step 3 — the root is anchored on Polygon.
  const rpcs = packet.polygon.chain === "polygon" ? POLYGON_RPCS : AMOY_RPCS;
  const ts = await queryTimestamps(rpcs, packet.polygon.stamperContract, packet.merkle.root);
  if (ts === 0n) {
    die(`root not anchored: timestamps(root) returned 0 on ${packet.polygon.stamperContract}`);
  }
  const when = new Date(Number(ts) * 1000).toISOString();
  console.log(green("✓") + ` step 3  anchored on Polygon at ${when} ${dim("(" + packet.polygon.stamperContract + ")")}`);

  // Step 4 — Bitcoin OTS (informational).
  if (packet.bitcoin?.openTimestamps) {
    console.log(dim(`· step 4  Bitcoin OpenTimestamps proof present (${packet.bitcoin.status}). Verify with: ots verify proof.ots`));
  }

  console.log("\n" + green("VERIFIED") + ` — document anchored ${when}, independently of BAScribe.`);
}

main().catch((e) => die(e.message || String(e)));
