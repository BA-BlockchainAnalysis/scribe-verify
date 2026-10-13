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
// Signature receipts (documents BAScribe never received, signed on their hash):
//   node verify.mjs --receipt <receipt.jws> [document.pdf]
//   node verify.mjs --receipt <receipt.jws> [document.pdf] --jwks <jwks.json> --packet <packet.json>
// See "Signature receipts" in the README for what this does and does not prove.
//
// The Merkle scheme matches BAScribe's src/lib/merkle.ts exactly:
//   SHA-256 leaves -> merkletreejs with keccak256 hashFn and sortPairs:true.

import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
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

// BAScribe's receipt-signing keys (Ed25519 public keys). Pinned here so a
// receipt verifies without asking bascribe.com for the key. A receipt signed
// with a key not listed needs --jwks, or falls back to fetching
// https://bascribe.com/.well-known/jwks.json (and says so).
const PINNED_KEYS = [
  { kty: "OKP", crv: "Ed25519", kid: "1be1cf24eb5e33db", x: "UPDOQdVSfLLx2R1pPXZs_fd4AuiJAMwYzsoLxyr6rcY" },
];
const JWKS_URL = "https://bascribe.com/.well-known/jwks.json";
const RECEIPT_TYP = "bascribe-signature-receipt+jws";
const RECEIPT_FORMAT = "bascribe-signature-receipt/1.0";

const green = (s) => `\x1b[32m${s}\x1b[0m`;
const yellow = (s) => `\x1b[33m${s}\x1b[0m`;
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

// Merkle inclusion + on-chain anchor for one leaf. Returns the anchoring time
// (ISO). `n` is the number of the first of the two steps it prints.
async function verifyAnchor(leaf, packet, n) {
  // Merkle proof folds to the root.
  const computedRoot = foldProof(leaf, packet.merkle.proof || []);
  if (computedRoot.toLowerCase() !== String(packet.merkle.root).toLowerCase()) {
    die(`Merkle proof folds to ${computedRoot}, not the packet root ${packet.merkle.root}`);
  }
  console.log(green("✓") + ` step ${n}  Merkle proof reproduces the batch root`);

  // The root is anchored on Polygon.
  const rpcs = packet.polygon.chain === "polygon" ? POLYGON_RPCS : AMOY_RPCS;
  const ts = await queryTimestamps(rpcs, packet.polygon.stamperContract, packet.merkle.root);
  if (ts === 0n) {
    die(`root not anchored: timestamps(root) returned 0 on ${packet.polygon.stamperContract}`);
  }
  const when = new Date(Number(ts) * 1000).toISOString();
  console.log(green("✓") + ` step ${n + 1}  anchored on Polygon at ${when} ${dim("(" + packet.polygon.stamperContract + ")")}`);

  // Bitcoin OTS (informational).
  if (packet.bitcoin?.openTimestamps) {
    console.log(dim(`· step ${n + 2}  Bitcoin OpenTimestamps proof present (${packet.bitcoin.status}). Verify with: ots verify proof.ots`));
  }
  return when;
}

// ── Signature receipts ─────────────────────────────────────────────

async function loadKeys(jwksPath, kid) {
  if (jwksPath) {
    const jwks = JSON.parse(await readFile(jwksPath, "utf8").catch(() => die(`cannot read JWKS: ${jwksPath}`)));
    return { keys: jwks.keys || [], source: `file ${jwksPath}` };
  }
  if (PINNED_KEYS.some((k) => k.kid === kid)) return { keys: PINNED_KEYS, source: "key pinned in this tool" };
  const r = await fetch(JWKS_URL).catch(() => null);
  if (!r || !r.ok) die(`key ${kid} is not pinned in this tool and ${JWKS_URL} could not be fetched; pass --jwks <file>`);
  return { keys: (await r.json()).keys || [], source: `fetched from ${JWKS_URL}` };
}

// Fetches the anchoring packet of a hash. null = not anchored (yet).
async function fetchPacketOrNull(hash) {
  const r = await fetch(`https://bascribe.com/api/verify/${hash}/packet`).catch(() => null);
  if (!r) die("could not reach bascribe.com to look up the anchor; pass --packet <file>");
  if (r.status === 404) return null;
  if (!r.ok) die(`could not fetch the anchoring packet (HTTP ${r.status})`);
  return r.json();
}

async function verifyReceipt({ receiptPath, filePath, jwksPath, packetArg }) {
  const raw = await readFile(receiptPath).catch(() => die(`cannot read receipt: ${receiptPath}`));
  // The anchored value is the hash of the file exactly as issued. A trailing
  // newline added by an editor or a shell redirect is tolerated.
  const jws = raw.toString("utf8").trim();
  const parts = jws.split(".");
  if (parts.length !== 3) die("not a compact JWS (expected three dot-separated parts)");

  let header, payload;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    die("receipt header or payload is not valid JSON");
  }
  if (header.alg !== "EdDSA") die(`unsupported signature algorithm: ${header.alg}`);
  if (header.typ !== RECEIPT_TYP) die(`not a BAScribe signature receipt (typ ${header.typ})`);
  if (payload.format !== RECEIPT_FORMAT) die(`unsupported receipt format: ${payload.format}`);

  // Step 1 — BAScribe's signature over the receipt.
  const { keys, source } = await loadKeys(jwksPath, header.kid);
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) die(`no key with kid ${header.kid} (${source})`);
  const publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
  const signed = Buffer.from(parts[0] + "." + parts[1]);
  if (!verifySignature(null, signed, publicKey, Buffer.from(parts[2], "base64url"))) {
    die("receipt signature is NOT valid: the receipt was altered or was not issued by this key");
  }
  console.log(green("✓") + ` step 1  receipt signed by BAScribe key ${header.kid} ${dim("(" + source + ")")}`);

  // Step 2 — the document you hold is the one that was signed.
  if (filePath) {
    const buf = await readFile(filePath).catch(() => die(`cannot read file: ${filePath}`));
    const docHash = sha256Hex(buf);
    if (docHash !== String(payload.document?.sha256).toLowerCase()) {
      die(`document hash ${docHash} does not match the receipt's document.sha256 ${payload.document?.sha256}`);
    }
    console.log(green("✓") + " step 2  document SHA-256 matches the receipt");
  } else {
    console.log(dim("· step 2  skipped (no document supplied) — the receipt names " + payload.document?.sha256));
  }

  // Steps 3-4 — the receipt's own hash is anchored on-chain.
  const receiptHash = sha256Hex(Buffer.from(jws, "utf8"));
  console.log(`receipt SHA-256 ${dim(receiptHash)}`);
  const packet = packetArg ? await loadPacket(packetArg) : await fetchPacketOrNull(receiptHash);
  let when = null;
  if (!packet) {
    console.log(yellow("!") + " step 3  receipt hash not anchored yet (anchoring follows completion by a few minutes)");
  } else {
    if (!packet?.merkle?.root || !packet?.polygon?.stamperContract) die("packet missing merkle/polygon fields");
    if (String(packet.documentHash).toLowerCase() !== receiptHash) {
      die(`packet is for ${packet.documentHash}, not for this receipt (${receiptHash})`);
    }
    when = await verifyAnchor(receiptHash, packet, 3);
  }

  // What the receipt states. Printed only after the signature checked out.
  console.log("\nThe receipt states:");
  console.log(`  request        ${payload.requestId}${payload.testMode ? yellow("  (TEST MODE)") : ""}`);
  console.log(`  document       ${payload.document?.title ?? ""}${payload.document?.version ? " (version " + payload.document.version + ")" : ""}`);
  console.log(`  document hash  ${payload.document?.sha256}`);
  console.log(`  level          ${payload.signatureLevel} — ${payload.signatureLevelLabel}`);
  for (const s of payload.signers || []) {
    console.log(`  signer ${s.order + 1}       ${s.name} <${s.email}>`);
    console.log(`                 email verified ${s.verification?.verifiedAt} (${s.verification?.method}), signed ${s.signedAt}`);
  }
  console.log(`  completed      ${payload.completedAt}`);

  if (when) {
    console.log("\n" + green("VERIFIED") + ` — receipt issued by BAScribe, unaltered, and anchored ${when}.`);
  } else {
    console.log("\n" + green("SIGNATURE VALID") + " — receipt issued by BAScribe and unaltered. " + yellow("Anchor not found yet") + ": run again later.");
  }
}

async function main() {
  const args = process.argv.slice(2);
  let filePath = null;
  let packetArg = null;
  let receiptPath = null;
  let jwksPath = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--packet") packetArg = args[++i];
    else if (args[i] === "--receipt") receiptPath = args[++i];
    else if (args[i] === "--jwks") jwksPath = args[++i];
    else if (!filePath) filePath = args[i];
    else packetArg = args[i];
  }
  if (receiptPath) return verifyReceipt({ receiptPath, filePath, jwksPath, packetArg });
  if (!filePath && !packetArg) {
    console.log("Usage: node verify.mjs <file.pdf | 0x-hash> [packet.json]");
    console.log("       node verify.mjs --receipt <receipt.jws> [document.pdf] [--jwks jwks.json] [--packet packet.json]");
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

  const when = await verifyAnchor(leaf, packet, 2);

  console.log("\n" + green("VERIFIED") + ` — document anchored ${when}, independently of BAScribe.`);
}

main().catch((e) => die(e.message || String(e)));
