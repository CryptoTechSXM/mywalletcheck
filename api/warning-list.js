/**
 * Opt-in community warning list.
 *
 *   POST   /api/warning-list   { address, attacker, sweeper, consent:true }
 *          -> queues a submission for maintainer review (status: pending)
 *   GET    /api/warning-list
 *          -> returns only PUBLISHED entries (address, attacker, sweeper)
 *   DELETE /api/warning-list   { address }
 *          -> removes a submission (honors removal requests)
 *
 * Why a real datastore and not Git: publishing a victim's address to a public
 * repo is permanent — Git history preserves it even after deletion, which
 * breaks the "removable on request" promise and creates a target list for
 * recovery-scam operators who hunt known victims. KV lets us truly delete.
 *
 * Consent is required. A maintainer flips status to "published" after review;
 * nothing a user submits appears publicly until then.
 *
 * Requires Vercel KV: `vercel kv create`, then the KV_* env vars are injected.
 */

import { kv } from "@vercel/kv";

const isAddress = (a) => typeof a === "string" && /^0x[a-fA-F0-9]{40}$/.test(a);
const lc = (a) => String(a).toLowerCase();
const key = (addr) => `warn:${lc(addr)}`;

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", process.env.ALLOW_ORIGIN || "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();

  try {
    if (req.method === "POST") {
      const { address, attacker, sweeper, consent } = req.body || {};
      if (consent !== true) return res.status(400).json({ error: "Consent is required." });
      if (!isAddress(address)) return res.status(400).json({ error: "Not a valid wallet address." });

      const record = {
        address: lc(address),
        attacker: isAddress(attacker) ? lc(attacker) : null,
        sweeper: isAddress(sweeper) ? lc(sweeper) : null,
        submitted: new Date().toISOString(),
        status: "pending", // maintainer sets "published" after review
      };
      await kv.set(key(address), record);
      await kv.sadd("warn:index", key(address));
      return res.status(200).json({ ok: true, message: "Queued for review." });
    }

    if (req.method === "GET") {
      const keys = await kv.smembers("warn:index");
      if (!keys?.length) return res.status(200).json([]);
      const records = await Promise.all(keys.map((k) => kv.get(k)));
      const published = records
        .filter((r) => r && r.status === "published")
        .map(({ address, attacker, sweeper }) => ({ address, attacker, sweeper }));
      res.setHeader("Cache-Control", "public, s-maxage=300, stale-while-revalidate=300");
      return res.status(200).json(published);
    }

    if (req.method === "DELETE") {
      const { address } = req.body || {};
      if (!isAddress(address)) return res.status(400).json({ error: "Not a valid wallet address." });
      await kv.del(key(address));
      await kv.srem("warn:index", key(address));
      return res.status(200).json({ ok: true, message: "Removed." });
    }

    return res.status(405).json({ error: "Method not allowed." });
  } catch (err) {
    console.error("warning-list error:", err.message);
    return res.status(500).json({ error: "Request could not be processed." });
  }
}
