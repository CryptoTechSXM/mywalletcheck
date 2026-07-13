/**
 * Core scan logic, shared by the API routes.
 *
 * Read-only. Never accepts, stores, transmits, or requests a private key or
 * seed phrase. There is no code path here that should ever change that.
 *
 * How detection works:
 *   1. CURRENT state (reliable): read the account's on-chain code via
 *      eth_getCode. A delegated EOA's code is `0xef0100` + the 20-byte delegate
 *      address (EIP-7702 delegation designator). Empty code (`0x`) = not
 *      delegated. This is deterministic and authoritative for "right now".
 *   2. CLASSIFY the delegate: malicious (on the sweeper list), known-benign
 *      (legitimate wallet delegators), or unknown.
 *   3. PAST signal (best-effort, clearly labelled): whether the address has any
 *      type-4 (EIP-7702) transactions in its history. This can miss sponsored
 *      delegations (where someone else paid gas), so it is only ever a "possible
 *      past delegation" hint -- never stated as fact.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// Read the drainer list with fs rather than a JSON import assertion.
// Import assertions crash the function on some Vercel/Node runtimes.
const __dirname = dirname(fileURLToPath(import.meta.url));
const sweepers = JSON.parse(readFileSync(join(__dirname, "../data/sweepers.json"), "utf8"));

const SWEEPERS = sweepers.contracts; // keys are lowercase addresses
const DELEGATION_PREFIX = "0xef0100"; // EIP-7702 designator prefix

// Known-legitimate EIP-7702 delegator contracts. A delegation to one of these
// is expected and reassuring, not alarming. Lowercase addresses.
// All verified from their Etherscan contract pages.
const KNOWN_BENIGN = {
  "0x63c0c19a282a1b52b07dd5a65b58948a07dae32b": "MetaMask",
  "0x000000009b1d0af20d8c6d0a44e162d11f9b8f00": "Uniswap",
  "0x80296ff8d1ed46f8e3c7992664d13b833504c2bb": "OKX",
};

export const CHAINS = {
  ethereum: { id: 1,    name: "Ethereum" },
  bsc:      { id: 56,   name: "BNB Chain" },
  polygon:  { id: 137,  name: "Polygon" },
  base:     { id: 8453, name: "Base" },
};

const EXPLORER = "https://api.etherscan.io/v2/api";

export const isAddress = (a) => typeof a === "string" && /^0x[a-fA-F0-9]{40}$/.test(a);
const lc = (a) => String(a).toLowerCase();

function apiKey() {
  const k = process.env.ETHERSCAN_KEY;
  if (!k) throw new Error("Missing ETHERSCAN_KEY");
  return k;
}

// Small fetch helper with retry, so a transient blip doesn't flip results.
async function getJson(url, label) {
  const MAX_TRIES = 3;
  let lastError;
  for (let attempt = 1; attempt <= MAX_TRIES; attempt++) {
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`${label} returned ${res.status}`);
      return await res.json();
    } catch (err) {
      lastError = err;
      if (attempt < MAX_TRIES) await new Promise((r) => setTimeout(r, 400 * attempt));
    }
  }
  throw lastError;
}

/**
 * Read the current delegation state for an address on one chain.
 * Returns { delegated: bool, delegate: address|null }.
 * Throws on a persistent failure (so the caller marks the chain "unchecked",
 * never silently "clean").
 */
async function getDelegation(address, chainKey) {
  const chain = CHAINS[chainKey];
  const url =
    `${EXPLORER}?chainid=${chain.id}&module=proxy&action=eth_getCode` +
    `&address=${address}&tag=latest&apikey=${apiKey()}`;

  const body = await getJson(url, `eth_getCode ${chainKey}`);

  // Explicit JSON-RPC error object.
  if (body.error) throw new Error(`${chainKey}: ${body.error.message || "proxy error"}`);

  const result = body.result;

  // Etherscan sometimes returns error/notice text in `result` instead of a
  // JSON-RPC error (e.g. "Max rate limit reached", "Invalid API Key", NOTOK,
  // or a restricted-access message). The ONLY valid results are a hex string
  // that is either empty code (0x) or a delegation designator (0xef0100...).
  // Anything else must be treated as "couldn't check" (throw -> unchecked),
  // never silently as "no delegation" — a false "clean" on a compromised
  // wallet is the worst possible failure for this tool.
  if (typeof result !== "string" || !/^0x[0-9a-fA-F]*$/.test(result)) {
    throw new Error(`${chainKey}: unexpected eth_getCode result: ${String(result).slice(0, 80)}`);
  }

  const code = result.toLowerCase();

  // Empty code: genuinely not delegated.
  if (code === "0x") return { delegated: false, delegate: null };

  // Delegation designator: 0xef0100 + 20-byte (40-hex) address = 47 bytes total.
  if (code.startsWith(DELEGATION_PREFIX)) {
    const delegate = "0x" + code.slice(DELEGATION_PREFIX.length, DELEGATION_PREFIX.length + 40);
    return { delegated: true, delegate: lc(delegate) };
  }

  // Any other non-empty code is a genuine deployed contract, not a 7702
  // delegation — for our purposes, not delegated.
  return { delegated: false, delegate: null };
}

/**
 * Best-effort check for PAST delegation activity: any type-4 (EIP-7702)
 * transactions in history? Labelled as a hint only. Never throws -- a failure
 * just means "couldn't determine", reported honestly rather than as "none".
 */
async function getPastSignal(address, chainKey) {
  try {
    const chain = CHAINS[chainKey];
    const url =
      `${EXPLORER}?chainid=${chain.id}&module=account&action=txlist` +
      `&address=${address}&startblock=0&endblock=99999999&sort=asc&apikey=${apiKey()}`;
    const body = await getJson(url, `txlist ${chainKey}`);
    if (body.status !== "1" && body.message !== "No transactions found") return null;
    const txs = Array.isArray(body.result) ? body.result : [];
    return txs.some((t) => String(t.type) === "4" || t.authorizationList);
  } catch {
    return null; // couldn't determine
  }
}

/** Classify a delegate address. */
function classifyDelegate(delegate) {
  if (SWEEPERS[delegate]) {
    return { verdict: "malicious", label: SWEEPERS[delegate].note || "Known drainer contract" };
  }
  if (KNOWN_BENIGN[delegate]) {
    return { verdict: "benign", label: `${KNOWN_BENIGN[delegate]} (legitimate delegator)` };
  }
  return { verdict: "unknown", label: "Unrecognized contract -- not on our known-malicious or known-safe lists" };
}

/** Scan a single chain. Returns a structured result, or throws (-> unchecked). */
async function scanChain(address, chainKey) {
  const chainName = CHAINS[chainKey].name;
  const { delegated, delegate } = await getDelegation(address, chainKey);

  if (delegated) {
    const { verdict, label } = classifyDelegate(delegate);
    const status =
      verdict === "malicious" ? "compromised"
      : verdict === "benign" ? "delegated-benign"
      : "delegated-unknown";
    return { chainName, status, delegated: true, delegate, delegateLabel: label };
  }

  const past = await getPastSignal(address, chainKey);
  return {
    chainName,
    status: past === true ? "past-delegation" : "clear",
    delegated: false,
    delegate: null,
    pastSignal: past, // true | false | null(unknown)
  };
}

export async function scanAddress(address, chain = "all") {
  const targets = chain === "all" ? Object.keys(CHAINS) : [chain];

  const settled = await Promise.allSettled(
    targets.map((c) => scanChain(address, c))
  );

  const results = [];
  const unchecked = [];
  settled.forEach((r, i) => {
    if (r.status === "fulfilled") results.push(r.value);
    else unchecked.push(CHAINS[targets[i]].name);
  });

  if (results.length === 0) {
    throw new Error(`All requested networks failed: ${unchecked.join(", ")}`);
  }

  const rank = {
    compromised: 5,
    "delegated-unknown": 4,
    "past-delegation": 3,
    "delegated-benign": 2,
    clear: 1,
  };
  results.sort((a, b) => (rank[b.status] || 0) - (rank[a.status] || 0));

  return { ...results[0], unchecked, perChain: results };
}
