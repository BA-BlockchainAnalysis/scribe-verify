# scribe-verify

**Trustless, open-source verifier for [BAScribe](https://bascribe.com) documents.**

Confirms that a signed PDF is anchored on-chain **without trusting BAScribe**. Every
input it needs is public: the proof packet, the smart contract, and the blockchain.
The only network call is a read-only `eth_call` to a public Polygon RPC.

## What it checks

1. **File integrity** — `SHA-256(your PDF)` equals the Merkle leaf in the proof packet.
2. **Merkle inclusion** — folding that leaf with the Merkle proof (keccak256 over
   sorted 32-byte pairs) reproduces the batch Merkle root.
3. **On-chain anchor** — the BAScribe Stamper contract on Polygon returns a non-zero
   `timestamps(root)`; that value is the Unix time the root was anchored.
4. **Bitcoin (optional)** — the packet also carries an OpenTimestamps proof you can
   verify with the standalone [`ots`](https://github.com/opentimestamps/opentimestamps-client) client.

BAScribe anchors to its **own** Stamper contract, distinct from BA | Stamp's:

```
Polygon mainnet: 0x6f10aabb44eabe395769f3b5a9bd52a2c599e5fd
```

The Merkle scheme is identical to BAScribe's `src/lib/merkle.ts`: SHA-256 leaves,
`merkletreejs` with a keccak256 hash function and `sortPairs: true`.

## Usage

```bash
npm install            # one dependency: js-sha3

# Hash the file and fetch its proof packet from bascribe.com automatically:
node verify.mjs ./executed.pdf

# Or use a packet you downloaded yourself (fully offline except the RPC read):
node verify.mjs ./executed.pdf ./bascribe-proof-XXXX.json

# Verify a packet without the file (skips the file-integrity step):
node verify.mjs --packet ./bascribe-proof-XXXX.json
```

Point it at a different RPC if you prefer your own node:

```bash
POLYGON_RPC_URL=https://your-node node verify.mjs ./executed.pdf
```

## Getting a proof packet

Any executed BAScribe document exposes one at:

```
https://bascribe.com/api/verify/<0x-sha256-of-the-pdf>/packet
```

or via the **Download proof packet** button on the document and public verify pages.

## Trust model

`scribe-verify` never contacts BAScribe to *decide* anything. It reads the proof you
already hold, recomputes the Merkle root itself, and asks a public Polygon node whether
that root is anchored. Even if bascribe.com disappeared, a packet you saved plus this
tool (or any Polygon block explorer) is enough to prove your document existed and was
unaltered.

## License

MIT.
