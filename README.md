# Agent Games — Proof Gatekeeper agent

A Vercel serverless function (Node.js) that plays **Proof Gatekeeper** for
zkVerify Agent Games: it receives signed task envelopes, decides
APPROVE/REJECT with deterministic checks, and returns a locally generated
Groth16 proof (snarkjs) for the platform to re-verify.

Built for one goal: complete **at least one scored task** so the
"at least one scored agent" prize-eligibility item is satisfied.

## Protocol (verified against the live /build page, 2026-11-15)

- **One endpoint.** The platform POSTs to the URL exactly as registered.
  Requests are distinguished by the `type` field in the signed JSON body —
  there are NO separate `/health` or `/task` paths:
  - `{ "type": "agent-games.preflight.v1", "agent_id", "issued_at", "nonce" }`
    → respond `{ "ok": true, "protocolVersion": "v1" }` (signed).
  - `{ "type": "agent-games.proof-gatekeeper.v1", "task_id", "mode",
    "issued_at", "deadline_at", "input": {...} }` → respond
    `{ "decision": "APPROVE"|"REJECT", "reason_code", "proof",
    "public_signals" }` (signed).
- **HMAC.** Header `x-agent-games-signature` = hex(HMAC-SHA256(secret,
  raw body)). Verified BEFORE parsing; every response is signed the same
  way. Secret env var: `AGENT_GAMES_HMAC_SECRET` (from the dashboard
  "Rotate Secret"). Missing secret = fail closed (500, nothing processed).
- **Task input (snake_case):** `registered_vk`, `proof_vk`, `minimum`,
  `public_balance`, `expiry_block`, `current_block`, `recipient`,
  `condition_recipient`, `amount`, `max_transfer`, `proof_tx`.
- **Decision — ALL five checks must pass to APPROVE:**
  1. `registered_vk == proof_vk` (else `VK_SUBSTITUTION`)
  2. `public_balance >= minimum` (else `INSUFFICIENT_BALANCE`)
  3. `current_block < expiry_block` (else `EXPIRED`)
  4. `recipient == condition_recipient` (else `RECIPIENT_MISMATCH`)
  5. `amount <= max_transfer` (else `AMOUNT_EXCEEDS_MAX`)
  Only `VK_SUBSTITUTION` is confirmed verbatim on the /build page; the other
  reason codes are descriptive (the platform scores the decision, not the
  code). Boundary semantics (`>=`, `<`, `<=`) were validated against the
  circuit itself — a wrong decision cannot produce a valid proof.
- **No zkVerify/Kurier submission.** The response carries the locally
  generated proof only; `proof_tx` is omitted (optional audit pointer).
- **Deterministic.** The proof salt is `keccak256("agent-games-gatekeeper-salt:" + task_id)`
  mod the field prime, so the same task always yields identical public
  signals. (Groth16 proof *bytes* still vary run to run — randomized
  blinding is inherent to the scheme; both proofs verify.)
- **taskId mapping.** Numeric `task_id` values are used as-is; string ids
  (e.g. `gk_8d31_...`) are `keccak256(task_id)` mod the field prime (keccak
  is the platform's house hash — Steal the VFY's publicInputsHash is
  keccak256 of ABI-packed fields). This mapping is an assumption: the
  platform does not document it. If the platform recomputes the taskId
  signal differently, proofs would still verify cryptographically but the
  signal check could fail — watch the first practice task result.
- **Timestamps.** `issued_at` more than 5 minutes from now → 401.
  Missing/unparseable `issued_at` is tolerated (HMAC already authenticates
  the sender).

## Layout

```
api/agent.js                  Vercel function: POST handler (preflight + task), GET liveness
api/lib/hmac.js               HMAC-SHA256 sign/verify (timing-safe compare)
api/lib/gatekeeper.js         decision logic, field mapping, snarkjs proving
api/circuits/gatekeeper.wasm  official circuit (1,755,820 bytes)
api/circuits/gatekeeper_final.zkey  official proving key (309,750 bytes)
api/circuits/verification_key.json  for local verification only
test/harness.js               full local test suite (111 checks)
test/serve.js                 tiny local dev server (manual smoke tests)
vercel.json                   maxDuration 10, includeFiles circuits, /agent rewrite
```

## Local test

```bash
npm install
npm test
```

Expected: `111/111 passed`, task end-to-end wall time ~300–1200 ms
(first task is slowest — wasm compile; warm tasks ~300–400 ms).

Manual smoke test:

```bash
AGENT_GAMES_HMAC_SECRET=test-secret node test/serve.js
curl http://127.0.0.1:3000/api/agent   # -> {"ok":true,"service":"agent-games-gatekeeper",...}
```

## Deploy

```bash
cd ~/workspace/agent-games/agent
vercel --prod --token "$VERCEL_TOKEN" --yes
vercel env add AGENT_GAMES_HMAC_SECRET production --token "$VERCEL_TOKEN"
# (paste the one-time secret from the Agent Games dashboard "Rotate Secret",
#  then redeploy so the new env var is picked up)
vercel --prod --token "$VERCEL_TOKEN" --yes
```

Public URL shape: `https://<project>.vercel.app/api/agent`
(also reachable as `https://<project>.vercel.app/agent` via the rewrite —
register either one as the agent endpoint).

Then, in the Agent Games dashboard: register the agent with that endpoint,
run **preflight** (must pass before the agent goes active), then dispatch a
**practice task** to confirm a scored-shaped response, then enter
Proof Gatekeeper for a scored round.

See `DEPLOY-NOTE.md` for the full deploy checklist and Vercel Hobby limits.
