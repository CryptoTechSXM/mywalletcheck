/**
 * Core scan logic, shared by the API routes.
 *
 * Read-only. Never accepts, stores, transmits, or requests a private key or
 * seed phrase. There is no code path here that should ever change that.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// Read the drainer list with fs rather than a JSON import assertion.
// Import assertions (`assert { type: "json" }`) crash the function on some
// Vercel/Node runtime versions; reading the file directly works everywhere.
const __dirname = dirname(fileURLToPath(import.meta.url));
const sweepers = JSON.parse(readFileSync(join(__dirname, "../data/sweepers.json"), "utf8"));

const SWEEPERS = sweepers.contracts;
const NULL_ADDRESS = "0x0000000000000000000000000000000000000000";

export const CHAINS = {
  ethereum: { id: 1,   name: "Ethereum",  keyEnv: "ETHERSCAN_KEY" },
  bsc:      { id: 56,  name: "BNB Chain", keyEnv: "BSCSCAN_KEY" },
  polygon:  { id: 137, name: "Polygon",   keyEnv: "POLYGONSCAN_KEY" },
};

// Etherscan V2 multichain endpoint serves all supported chains via chainid.
const EXPLORER = "https://api.etherscan.io/v2/api";

export const isAddress = (a) => typeof a === "string" && /^0x[a-fA-F0-9]{40}$/.test(a);
const lc = (a) => String(a).toLowerCase();

/**
 * Fetch EIP-7702 authorizations where `address` is the authority.
 *
 * Explorer support for authorization lists is uneven and changing; verify the
 * response shape against current docs. Long term, run your own type-0x04
 * indexer. Critical: on any failure this THROWS. It must never return an empty
 * result that a caller could interpret as "clean" — a compromised user told
 * "nothing found" when nothing was checked is worse off than before.
 */
async function fetchAuthorizations(address, chainKey) {
  const chain = CHAINS[chainKey];
  // The Etherscan V2 key works across all supported chains, so fall back to it
  // when a chain-specific key isn't set. This lets a single ETHERSCAN_KEY cover
  // Ethereum, BSC, and Polygon with no extra configuration.
  const apikey = process.env[chain.keyEnv] || process.env.ETHERSCAN_KEY;
  if (!apikey) throw new Error(`Missing ${chain.keyEnv} (and no ETHERSCAN_KEY fallback)`);

  const url =
    `${EXPLORER}?chainid=${chain.id}&module=account&action=txlist` +
    `&address=${address}&startblock=0&endblock=99999999&sort=asc&apikey=${apikey}`;

  // Retry transient failures (rate limits, momentary "NOTOK", network blips)
  // before giving up. Without this, the same address can return different
  // results on refresh depending on whether a chain happened to respond.
  // Only a persistent failure (e.g. a key with no access to this chain) throws.
  const MAX_TRIES = 3;
  let lastError;
  for (let attempt = 1; attempt <= MAX_TRIES; attempt++) {
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Explorer ${chainKey} returned ${res.status}`);
      const body = await res.json();

      if (body.status !== "1" && body.message !== "No transactions found") {
        throw new Error(`Explorer ${chainKey}: ${body.message || "unknown error"}`);
      }
      const txs = Array.isArray(body.result) ? body.result : [];

      return txs
        .filter((t) => String(t.type) === "4" || t.authorizationList)
        .flatMap((t) =>
          (t.authorizationList || [])
            .filter((a) => lc(a.address ?? a.authority) === lc(address) || !a.authority)
            .map((a) => ({
              delegate: lc(a.address),
              sender: lc(t.from),
              nonce: Number(a.nonce),
              hash: t.hash,
              when: new Date(Number(t.timeStamp) * 1000).toISOString().slice(0, 10),
            }))
        );
    } catch (err) {
      lastError = err;
      if (attempt < MAX_TRIES) {
        // Brief backoff before retrying: 400ms, then 800ms.
        await new Promise((r) => setTimeout(r, 400 * attempt));
      }
    }
  }
  throw lastError;
}

function classify(auths, chainName) {
  // Sort authorizations chronologically before walking them. The explorer API
  // does not guarantee row order, and the verdict depends on the LAST state
  // (delegated vs revoked) — so without this sort the same address can classify
  // differently between runs depending on what order rows come back in.
  const ordered = [...auths].sort((a, b) => {
    if (a.when !== b.when) return a.when < b.when ? -1 : 1;
    return (a.nonce ?? 0) - (b.nonce ?? 0);
  });

  const events = [];
  let reDelegations = 0;
  let sweeper = null;
  let attacker = null;
  let seenHostile = false;

  for (const a of ordered) {
    const revoke = a.delegate === NULL_ADDRESS;
    const hostile = !revoke && !!SWEEPERS[a.delegate];

    if (hostile) {
      if (seenHostile) reDelegations++;
      seenHostile = true;
      sweeper = a.delegate;
      attacker = a.sender;
      events.push({
        when: a.when, kind: "hostile", tx: a.hash,
        what: "Delegated to a known drainer contract",
        who: `Set by ${a.sender}`,
      });
    } else if (revoke && seenHostile) {
      events.push({
        when: a.when, kind: "revoke", tx: a.hash,
        what: "Owner revoked the delegation",
        who: "Signed by the wallet owner",
      });
    }
    // Benign delegations (MetaMask, Bitget, TokenPocket, etc.) are deliberately
    // not surfaced — showing them alarms people for no reason.
  }

  if (!seenHostile) return { status: "clear" };

  const last = events[events.length - 1];
  return {
    status: last.kind === "hostile" ? "compromised" : "exposed",
    chainName, events, sweeper, attacker, reDelegations,
  };
}

export async function scanAddress(address, chain = "all") {
  const targets = chain === "all" ? Object.keys(CHAINS) : [chain];

  // Check each chain independently. A single chain failing (rate limit, outage,
  // a key without access to that chain) must NOT throw away results from the
  // chains that did respond — and must never be silently treated as "clean".
  const settled = await Promise.allSettled(
    targets.map(async (c) => classify(await fetchAuthorizations(address, c), CHAINS[c].name))
  );

  const results = [];
  const unchecked = [];
  settled.forEach((r, i) => {
    if (r.status === "fulfilled") results.push(r.value);
    else unchecked.push(CHAINS[targets[i]].name);
  });

  // If every requested chain failed, this is a real error — surface it so the
  // caller shows "couldn't check", never a false "clean".
  if (results.length === 0) {
    throw new Error(`All requested networks failed: ${unchecked.join(", ")}`);
  }

  const rank = { compromised: 2, exposed: 1, clear: 0 };
  results.sort((a, b) => rank[b.status] - rank[a.status]);

  // Return the worst finding, but attach the list of chains we could NOT check
  // so the UI can tell the user their result is partial. Absence of a finding
  // on an unchecked chain is not evidence of safety.
  return { ...results[0], unchecked };
}
