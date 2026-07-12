# WalletCheck

A free, read-only public tool that lets anyone check whether a wallet has been delegated to a known drainer contract under EIP-7702, harden it against future theft, and generate reports for exchanges and law enforcement.

No wallet connection. No signature request. No seed phrase — ever. It reads public blockchain records and nothing else.

## Layout

```
walletcheck/
├── public/
│   ├── index.html                 Delegation check + hardening guide + reporting
│   └── traced-theft-report.html   Report builder for thefts with a known suspect + CEX cash-out
├── api/
│   ├── scan.js                    POST /api/scan  — reads chain records, compares to drainer list
│   └── warning-list.js            Opt-in community warning list (Vercel KV)
├── lib/
│   └── scan.js                    Shared scan + classify logic
├── data/
│   └── sweepers.json              The drainer list — edit this by pull request
├── vercel.json
└── package.json
```

The split is deliberate:

- **`data/sweepers.json` is owned by Git.** It's public, auditable, and updated by pull request. This is the one file that determines whether the tool tells the truth, so it should be reviewable by anyone and carry the evidence for each entry.
- **Warning-list submissions live in Vercel KV, not Git.** User-submitted victim addresses must be truly deletable. Git history is permanent — an address committed once is retrievable forever, which would break the removal promise and create a target list for recovery-scam operators. KV lets a removal request actually remove.

## Deploy

1. **Push to GitHub.** Create a repo, commit this folder.

2. **Import into Vercel.** New Project → import the repo. Vercel detects the static `public/` front end and the `api/` serverless functions automatically. No build step.

3. **Add a KV store** (for the opt-in warning list):
   ```
   vercel kv create walletcheck-kv
   ```
   Link it to the project in the Vercel dashboard (Storage tab). This injects the `KV_*` env vars automatically. If you don't need the warning list yet, you can skip this — the scanner works without it.

4. **Add your explorer API keys** in Settings → Environment Variables:
   ```
   ETHERSCAN_KEY     = ...
   BSCSCAN_KEY       = ...
   POLYGONSCAN_KEY   = ...
   ```
   These are read only by the serverless functions via `process.env`. They never reach the client or the repo. (The single Etherscan V2 key works across all chains on many plans — check your plan and set the others if needed.)

5. **Attach your domain** on day one. A tool at `something.vercel.app` is trivial to imitate and hard for a wary victim to trust. Point your `.org` at the project (Settings → Domains) — HTTPS is automatic. Register the typo-variants and the `.com` too; if this catches on, someone will register a lookalike to phish the people coming to you for safety.

Local dev: `npm install && vercel dev`.

## Maintaining the drainer list

When a new sweeper contract turns up:

1. Confirm it — read a victim's authorization list and the drain transaction. Don't add on suspicion.
2. Add an entry to `data/sweepers.json` with the chain, first-seen date, and the evidence (a tx hash that proves it).
3. Open a PR. Once merged and deployed, every user is protected.
4. Report it to the relevant block explorer for public flagging too.

## Design rules that must not regress

- **A clean scan never says "safe."** It says *no malicious delegation detected*, with the caveat that a stolen key with no delegation attached yet looks identical to a healthy wallet. Overselling certainty to novices causes harm.
- **The scan fails loudly.** On explorer error the API returns 502 and the UI says "couldn't check, retry." It never degrades to a clean result.
- **No connect-wallet, ever.** The trust proposition for freshly-robbed users is that the tool asks for nothing. No future "connect for convenience" feature.
- **Benign delegations stay hidden.** MetaMask/Bitget/TokenPocket run legitimate delegators; surfacing them alarms people needlessly.
- **The tool never names a human attacker.** On-chain data doesn't reliably resolve to a person — drainer wallets are often themselves compromised. Reports produce evidence for investigators; they don't accuse.

## What it cannot do

Detect a stolen key with no delegation yet · see malicious token approvals · explain how keys leaked · identify the attacker · recover anything. Anyone offering paid crypto recovery is running the second scam. The tool says all of this, plainly, and should keep saying it.

---

Not financial or legal advice. Community-maintained.
