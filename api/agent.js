'use strict';
// Agent Games — Proof Gatekeeper agent (Vercel serverless function).
//
// ONE endpoint, distinguished by the `type` field in the signed JSON body
// (per https://agentgames.zkverify.io/build, verified 2026-11-15):
//   { "type": "agent-games.preflight.v1", ... }
//       -> { "ok": true, "protocolVersion": "v1" } (signed)
//   { "type": "agent-games.proof-gatekeeper.v1", "task_id", "input", ... }
//       -> { "decision": "APPROVE"|"REJECT", "reason_code", "proof",
//            "public_signals" } (signed)
//
// Security (fail closed):
// - Every inbound request is HMAC-SHA256 verified over the RAW body against
//   the x-agent-games-signature header BEFORE any parsing or work. 401 on
//   mismatch. Every response is signed the same way.
// - Secret comes ONLY from env AGENT_GAMES_HMAC_SECRET. Missing secret =
//   500, nothing is processed or signed.
// - issued_at freshness: 401 if present, parseable, and more than 5 minutes
//   from now (guards against replays). Missing/unparseable issued_at is
//   tolerated — HMAC already authenticates the sender.
// - Any failure in decision/proving fails closed to a signed REJECT with
//   reason_code INTERNAL_ERROR (no proof) instead of timing out.
// - No zkVerify/Kurier submission: the response carries the locally generated
//   Groth16 proof only; proof_tx is omitted (it is an optional audit pointer).

const { signHex, verifyHex } = require('./lib/hmac');
const gatekeeper = require('./lib/gatekeeper');

const TYPE_PREFLIGHT = 'agent-games.preflight.v1';
const TYPE_TASK = 'agent-games.proof-gatekeeper.v1';
const TIMESTAMP_TOLERANCE_MS = 5 * 60 * 1000;

function getSecret() {
  const s = process.env.AGENT_GAMES_HMAC_SECRET;
  return typeof s === 'string' && s.length > 0 ? s : null;
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendSigned(res, secret, status, obj) {
  const body = JSON.stringify(obj);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('x-agent-games-signature', signHex(secret, Buffer.from(body, 'utf8')));
  res.end(body);
}

function sendUnsigned(res, status, obj) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(obj));
}

function timestampFresh(envelope) {
  const raw = envelope && envelope.issued_at;
  if (raw === undefined || raw === null || raw === '') {
    return { ok: true, reason: 'missing' };
  }
  const t = Date.parse(raw);
  if (Number.isNaN(t)) return { ok: true, reason: 'unparseable' };
  const skew = Math.abs(Date.now() - t);
  return skew <= TIMESTAMP_TOLERANCE_MS
    ? { ok: true, reason: 'fresh' }
    : { ok: false, reason: `stale skew=${skew}ms` };
}

function handlePreflight(res, secret) {
  sendSigned(res, secret, 200, { ok: true, protocolVersion: 'v1' });
}

async function handleTask(res, secret, envelope) {
  const taskId = envelope.task_id;
  const input = envelope.input || {};

  let outcome;
  try {
    outcome = gatekeeper.decide(input);
  } catch (err) {
    console.error('[gatekeeper] decide failed', { taskId, error: err.message });
    return sendSigned(res, secret, 200, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR' });
  }

  let circuitInput;
  try {
    circuitInput = gatekeeper.toCircuitInput(taskId, input, outcome.decision);
  } catch (err) {
    console.error('[gatekeeper] input mapping failed', { taskId, error: err.message });
    return sendSigned(res, secret, 200, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR' });
  }

  try {
    const { proof, publicSignals, proveMs } = await gatekeeper.prove(circuitInput);
    console.log('[gatekeeper] task done', {
      taskId,
      decision: outcome.decision,
      reason: outcome.reasonCode,
      proveMs,
    });
    return sendSigned(res, secret, 200, {
      decision: outcome.decision === 1 ? 'APPROVE' : 'REJECT',
      reason_code: outcome.reasonCode,
      proof,
      public_signals: publicSignals,
    });
  } catch (err) {
    // Proving failed (e.g. decision/circuit mismatch) — fail closed with a
    // REJECT and no proof rather than timing out.
    console.error('[gatekeeper] prove failed', { taskId, error: err.message });
    return sendSigned(res, secret, 200, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR' });
  }
}

module.exports = async (req, res) => {
  try {
    // Liveness check for humans (no HMAC — reveals nothing sensitive).
    if (req.method === 'GET') {
      return sendUnsigned(res, 200, {
        ok: true,
        service: 'agent-games-gatekeeper',
        protocolVersion: 'v1',
      });
    }
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'GET, POST');
      return sendUnsigned(res, 405, { error: 'method_not_allowed' });
    }

    const secret = getSecret();
    if (!secret) {
      console.error('[agent] AGENT_GAMES_HMAC_SECRET is not set — failing closed');
      return sendUnsigned(res, 500, { error: 'server_misconfigured' });
    }

    const rawBody = await readRawBody(req);
    const signature = req.headers['x-agent-games-signature'];
    if (!verifyHex(secret, rawBody, signature)) {
      return sendUnsigned(res, 401, { error: 'unauthorized' });
    }

    let envelope;
    try {
      envelope = JSON.parse(rawBody.toString('utf8'));
    } catch {
      return sendUnsigned(res, 400, { error: 'invalid_json' });
    }
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
      return sendUnsigned(res, 400, { error: 'invalid_envelope' });
    }

    const ts = timestampFresh(envelope);
    if (!ts.ok) {
      console.error('[agent] stale timestamp', { type: envelope.type, reason: ts.reason });
      return sendUnsigned(res, 401, { error: 'stale_timestamp' });
    }

    if (envelope.type === TYPE_PREFLIGHT) return handlePreflight(res, secret);
    if (envelope.type === TYPE_TASK) return handleTask(res, secret, envelope);
    return sendUnsigned(res, 400, { error: 'unknown_type' });
  } catch (err) {
    console.error('[agent] unhandled error', err);
    if (!res.headersSent) return sendUnsigned(res, 500, { error: 'internal_error' });
  }
};
