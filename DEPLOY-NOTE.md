# Deployment note for the parent (deploy step — NOT done by the builder)

## What is ready

Repo: `~/workspace/agent-games/agent/` — a Vercel serverless function,
fully built and locally tested (111/111 harness checks pass). NOT deployed,
NO agent registered, nobody contacted. Waiting only for the Vercel token.

## Exact deploy commands

```bash
cd ~/workspace/agent-games/agent

# 1. Deploy (first deploy creates the project; note the URL it prints)
vercel --prod --token "$VERCEL_TOKEN" --yes

# 2. Set the HMAC secret (one-time plaintext from the Agent Games dashboard:
#    agent -> "Rotate Secret"). Production env only.
vercel env add AGENT_GAMES_HMAC_SECRET production --token "$VERCEL_TOKEN"
# (paste the secret when prompted; it is NOT stored in the repo)

# 3. Redeploy so the function picks up the new env var
vercel --prod --token "$VERCEL_TOKEN" --yes

# 4. Smoke test (no auth needed for the liveness GET)
curl https://<project>.vercel.app/api/agent
# expect: {"ok":true,"service":"agent-games-gatekeeper","protocolVersion":"v1"}
```

Get the token from the Vercel dashboard (Account Settings -> Tokens) or
`vercel login` on a machine with a browser. The token must be collected via
the Secure Vault, never in chat. If the deploy runs under the "musang" team,
add `--scope musang` (or the team's slug) to each command.

## Expected public URL

- `https://<project>.vercel.app/api/agent` (canonical)
- `https://<project>.vercel.app/agent` (same function, via the vercel.json
  rewrite — matches the dashboard placeholder `my-agent.fly.dev/agent`)

Register ONE of these as the agent endpoint in the Agent Games dashboard
(My agents -> Register agent), then run **preflight** from the dashboard.
Preflight must pass before the agent is marked active. Then dispatch a
**practice task** (unscored) to confirm the full loop, then enter
Proof Gatekeeper for a scored round.

## Vercel Hobby limits that could bite

- **10s function timeout (hard, cannot be raised on Hobby).**
  Measured locally: cold task ~1.15s, warm tasks ~0.30–0.40s end-to-end
  (proving itself ~0.3–1.1s). Even a slow Vercel cold start (~1–3s) + cold
  proving leaves ~6s of headroom. Preflight has its own 10s platform
  window and answers in ~12ms warm (no proving on that path).
- **Function bundle 50 MB.** Traced bundle is **5.33 MB** total (3.36 MB
  code/deps + 1.97 MB circuit artifacts) — ~11% of the limit. Verified
  with `@vercel/nft` before deploy.
- **Cold starts.** Vercel freezes idle functions; the first request after
  idle pays ~1–3s. Harmless here (60s task deadline, 10s preflight window).
  No keep-warm is needed, but if preflight ever flakes on a cold start,
  hit the GET liveness URL once first to warm the function, then preflight.
- **No background work / no cron needed.** The agent is purely reactive.
- **Hobby = non-commercial use per Vercel ToS.** This is a personal
  competition entry, not a SaaS — fine.
- **Env var changes need a redeploy** (step 3 above). If the dashboard
  secret is ever rotated, update the env var AND redeploy, or every
  request will 401.

## Sequence after deploy (parent's job)

1. Deploy + set secret + redeploy (above).
2. Dashboard: register agent (name, event = Proof Gatekeeper, repo URL,
   endpoint URL). Save the one-time HMAC secret shown at registration —
   that is the value for step 2 above (order: register FIRST to get the
   secret, then set env + redeploy; or rotate secret after deploy).
3. Dashboard: run preflight -> must return ok. If it fails, check Vercel
   function logs (`vercel logs <url> --token ...`) — the agent logs
   HMAC/timestamp failures.
4. Dashboard: dispatch a practice task -> confirm the response scores
   (decision + verified proof). THIS is the moment the taskId-mapping
   assumption (below) gets its first real-world test.
5. Enter a scored Proof Gatekeeper round. One completed scored task flips
   the checklist item. The agent then keeps answering rounds automatically;
   no further action is needed unless it errors.

## Assumptions / open risks (flagged, not blocking)

1. **taskId mapping is an assumption.** The platform does not document how
   the string `task_id` (e.g. `gk_8d31_...`) maps to the circuit's numeric
   `taskId` signal. The agent uses keccak256(task_id) mod p (keccak is the
   platform's house hash). If the platform recomputes this signal
   differently, the proof still verifies cryptographically but a strict
   signal comparison could fail. Mitigation: the practice task will reveal
   this before any scored round.
2. **Reason codes.** Only `VK_SUBSTITUTION` is confirmed verbatim on
   /build. The other four codes are descriptive guesses; the platform
   scores the decision, not the code, so this is low-risk.
3. **No Kurier submission.** The agent returns the local proof only. The
   /build Security checklist mentions "finalized before approval" as a
   check, but that applies to the on-chain verification path (needs a
   Kurier API key, which we do not have). The platform re-verifies the
   proof itself against its own key, which is the scoring path described
   in the starter prompt. If the platform ever requires a proof_tx, that
   would need a Kurier key + a code change.
4. **HMAC secret format.** The secret is used as raw UTF-8 bytes (the
   standard for such webhook-style secrets). If the platform hex-decodes
   its secret before signing, verification would fail — the practice
   preflight would reveal this immediately (preflight 401s), and the fix
   is a one-line change in `api/lib/hmac.js`.
5. **Boundary semantics validated locally only.** The `>=` / `<` / `<=`
   boundary choices were proven against the circuit (a wrong decision
   cannot produce a valid proof, and all 4 boundary cases produced valid
   proofs), so they match the circuit. They should therefore match the
   platform's own scoring, which uses the same circuit.
