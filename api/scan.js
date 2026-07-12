/**
 * POST /api/scan   { address, chain }
 *   -> { status, chainName, events[], sweeper, attacker, reDelegations }
 *
 * Read-only. Queries public block explorer records for EIP-7702 delegations
 * and compares against the maintained drainer list in data/sweepers.json.
 */

import { scanAddress, isAddress, CHAINS } from "../lib/scan.js";

export default async function handler(req, res) {
  // Allow the static front end (same origin in production) to call this.
  res.setHeader("Access-Control-Allow-Origin", process.env.ALLOW_ORIGIN || "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Use POST." });

  const { address, chain = "all" } = req.body || {};

  if (!isAddress(address)) {
    return res.status(400).json({ error: "Not a valid wallet address." });
  }
  if (chain !== "all" && !CHAINS[chain]) {
    return res.status(400).json({ error: "Unknown network." });
  }

  try {
    const result = await scanAddress(address, chain);
    // Cache a clean/known result briefly — protects explorer rate limits and
    // speeds up repeat checks. Short TTL so a fresh compromise shows quickly.
    res.setHeader("Cache-Control", "public, s-maxage=180, stale-while-revalidate=120");
    return res.status(200).json(result);
  } catch (err) {
    // Never degrade to "clear" on failure.
    console.error("scan failed:", err.message);
    return res.status(502).json({ error: "Could not read chain records. Please retry." });
  }
}
