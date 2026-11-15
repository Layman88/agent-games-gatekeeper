'use strict';
// Local test harness for the Proof Gatekeeper agent.
// Spins up the real Vercel handler on a local HTTP server, sends SIGNED
// preflight + task envelopes (as the platform would), and asserts:
//   - correct decisions + reason codes for 1 valid task, all 5 trap types,
//     and 4 boundary cases (the circuit is the referee: a wrong decision
//     cannot produce a valid proof, so groth16.verify passing ALSO proves
//     the decision logic matches the circuit)
//   - every returned proof verifies against the local verification key
//   - public signals match the task inputs exactly
//   - response signatures verify; bad/missing signatures -> 401
//   - stale issued_at -> 401; determinism (same task -> identical public
//     signals, and the replay proof also verifies — Groth16 proofs are
//     randomized by design, so proof BYTES differ run to run; that is
//     expected, not a bug)
//   - per-task end-to-end wall time (must fit Vercel Hobby's 10s limit)
//
// Run:  npm test        (from ~/workspace/agent-games/agent)
// Exit: 0 = all pass, 1 = any failure.

process.env.AGENT_GAMES_HMAC_SECRET = 'test-secret-do-not-use-in-prod';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { keccak256 } = require('js-sha3');
const snarkjs = require('snarkjs');

const handler = require('../api/agent');
const { FIELD_PRIME } = require('../api/lib/gatekeeper');

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
const VK_REAL = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0'; // /api/circuit-info gatekeeper.vkHash
const VK_OTHER = '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047'; // vfyPolicy vkHash (a *different* key)
const RECIPIENT = '0xAd5f21a943Cfe8ccd2ed9a18609c29926a50c434'; // Agent Games wallet
const RECIPIENT_WRONG = '0x1111111111111111111111111111111111111111';
const VKEY = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'api', 'circuits', 'verification_key.json'), 'utf8')
);

const results = [];
const timings = [];

function check(name, ok, detail) {
  results.push({ name, ok: !!ok, detail: detail || '' });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`);
}

function sign(body) {
  return crypto.createHmac('sha256', SECRET).update(body).digest('hex');
}

function verifyResponseSignature(rawBody, sig) {
  if (!sig) return false;
  const expected = sign(rawBody);
  return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(sig, 'hex'));
}

function baseInput(overrides) {
  return Object.assign(
    {
      registered_vk: VK_REAL,
      proof_vk: VK_REAL,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0xa8b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
    },
    overrides || {}
  );
}

function taskEnvelope(taskId, input, extra) {
  return Object.assign(
    {
      type: 'agent-games.proof-gatekeeper.v1',
      task_id: taskId,
      mode: 'competition',
      issued_at: new Date().toISOString(),
      deadline_at: new Date(Date.now() + 60000).toISOString(),
      input,
    },
    extra || {}
  );
}

// Expected public signals, computed INDEPENDENTLY of the agent code.
function expectedSignals(taskId, input, decision) {
  const field = (v) => (((BigInt(v) % FIELD_PRIME) + FIELD_PRIME) % FIELD_PRIME).toString(10);
  const taskField = /^\d+$/.test(String(taskId))
    ? BigInt(String(taskId)).toString(10)
    : (BigInt('0x' + keccak256(String(taskId))) % FIELD_PRIME).toString(10);
  return [
    null, // [0] commitment — opaque, checked for shape only
    field(input.registered_vk),
    field(input.proof_vk),
    field(input.minimum),
    field(input.public_balance),
    field(input.expiry_block),
    field(input.current_block),
    field(input.recipient),
    field(input.condition_recipient),
    field(input.amount),
    field(input.max_transfer),
    String(decision),
    taskField,
  ];
}

async function post(port, obj, opts) {
  const o = opts || {};
  const raw = typeof obj === 'string' ? obj : JSON.stringify(obj);
  const headers = { 'Content-Type': 'application/json' };
  if (o.sign !== false) headers['x-agent-games-signature'] = o.signature || sign(raw);
  const t0 = Date.now();
  const res = await fetch(`http://127.0.0.1:${port}/api/agent`, {
    method: 'POST',
    headers,
    body: raw,
  });
  const ms = Date.now() - t0;
  const bodyText = await res.text();
  let body = null;
  try {
    body = JSON.parse(bodyText);
  } catch {
    /* non-JSON */
  }
  return { status: res.status, body, bodyText, sig: res.headers.get('x-agent-games-signature'), ms };
}

async function runTaskCase(port, name, taskId, input, wantDecision, wantReason) {
  const env = taskEnvelope(taskId, input);
  const r = await post(port, env);
  timings.push({ name, ms: r.ms });
  check(`${name}: HTTP 200`, r.status === 200, `got ${r.status}`);
  if (r.status !== 200) return null;
  check(`${name}: decision=${wantDecision}`, r.body.decision === wantDecision, `got ${r.body.decision}`);
  check(`${name}: reason_code=${wantReason}`, r.body.reason_code === wantReason, `got ${r.body.reason_code}`);
  check(`${name}: response signature valid`, verifyResponseSignature(r.bodyText, r.sig));
  const proofOkShape =
    r.body.proof &&
    Array.isArray(r.body.proof.pi_a) &&
    Array.isArray(r.body.proof.pi_b) &&
    Array.isArray(r.body.proof.pi_c) &&
    r.body.proof.protocol === 'groth16' &&
    r.body.proof.curve === 'bn128';
  check(`${name}: proof shape (groth16/bn128)`, proofOkShape);
  check(
    `${name}: 13 public signals`,
    Array.isArray(r.body.public_signals) && r.body.public_signals.length === 13,
    `got ${r.body.public_signals && r.body.public_signals.length}`
  );
  let verified = false;
  if (proofOkShape && r.body.public_signals) {
    try {
      verified = await snarkjs.groth16.verify(VKEY, r.body.public_signals, r.body.proof);
    } catch (e) {
      verified = false;
    }
  }
  check(`${name}: groth16.verify == true`, verified === true);
  // Public signals match the task inputs exactly (indices 1..12).
  if (r.body.public_signals) {
    const want = expectedSignals(taskId, input, wantDecision === 'APPROVE' ? 1 : 0);
    let sigMatch = true;
    let firstBad = -1;
    for (let i = 1; i <= 12; i++) {
      if (r.body.public_signals[i] !== want[i]) {
        sigMatch = false;
        firstBad = i;
        break;
      }
    }
    check(
      `${name}: public signals match inputs`,
      sigMatch,
      sigMatch ? '' : `index ${firstBad}: got ${r.body.public_signals[firstBad]}, want ${want[firstBad]}`
    );
    check(
      `${name}: commitment signal is a field element`,
      /^\d+$/.test(r.body.public_signals[0]) && BigInt(r.body.public_signals[0]) < FIELD_PRIME
    );
  }
  console.log(`      -> end-to-end ${r.ms}ms`);
  return r;
}

async function main() {
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  console.log(`harness server on 127.0.0.1:${port}\n`);

  try {
    // --- liveness ---
    const g = await fetch(`http://127.0.0.1:${port}/api/agent`);
    const gBody = await g.json();
    check('GET liveness 200 + ok', g.status === 200 && gBody.ok === true, `got ${g.status}`);

    // --- preflight: happy path ---
    const pf = {
      type: 'agent-games.preflight.v1',
      agent_id: 'agt_test',
      issued_at: new Date().toISOString(),
      nonce: 'abc123',
    };
    const rPf = await post(port, pf);
    check('preflight: HTTP 200', rPf.status === 200, `got ${rPf.status}`);
    check(
      'preflight: body {ok:true, protocolVersion:"v1"}',
      rPf.body && rPf.body.ok === true && rPf.body.protocolVersion === 'v1',
      JSON.stringify(rPf.body)
    );
    check('preflight: response signature valid', verifyResponseSignature(rPf.bodyText, rPf.sig));
    check('preflight: fast (<2s)', rPf.ms < 2000, `${rPf.ms}ms`);

    // --- preflight: auth failures ---
    const rBadSig = await post(port, pf, { signature: '0'.repeat(64) });
    check('preflight bad signature -> 401', rBadSig.status === 401, `got ${rBadSig.status}`);
    const rNoSig = await post(port, pf, { sign: false });
    check('preflight missing signature -> 401', rNoSig.status === 401, `got ${rNoSig.status}`);

    // --- stale timestamp ---
    const stale = taskEnvelope('gk_stale', baseInput(), {
      issued_at: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
    });
    const rStale = await post(port, stale);
    check('stale issued_at (10 min) -> 401', rStale.status === 401, `got ${rStale.status}`);

    // --- malformed ---
    const rBadJson = await post(port, '{not json', {});
    check('invalid JSON -> 400', rBadJson.status === 400, `got ${rBadJson.status}`);
    const rUnknown = await post(port, { type: 'agent-games.nope.v1', issued_at: new Date().toISOString() });
    check('unknown type -> 400', rUnknown.status === 400, `got ${rUnknown.status}`);

    // --- tasks: 1 valid + 5 traps + 4 boundary cases ---
    const rValid = await runTaskCase(port, 'valid APPROVE', 'gk_8d31f2a9c4', baseInput(), 'APPROVE', 'OK');
    await runTaskCase(port, 'trap expired', 'gk_trap_exp', baseInput({ current_block: 8430000 }), 'REJECT', 'EXPIRED');
    await runTaskCase(
      port,
      'trap wrong recipient',
      'gk_trap_recip',
      baseInput({ recipient: RECIPIENT_WRONG }),
      'REJECT',
      'RECIPIENT_MISMATCH'
    );
    await runTaskCase(
      port,
      'trap amount over max',
      'gk_trap_amt',
      baseInput({ amount: '1001' }),
      'REJECT',
      'AMOUNT_EXCEEDS_MAX'
    );
    await runTaskCase(
      port,
      'trap vk substitution',
      'gk_trap_vk',
      baseInput({ proof_vk: VK_OTHER }),
      'REJECT',
      'VK_SUBSTITUTION'
    );
    await runTaskCase(
      port,
      'trap insufficient balance',
      'gk_trap_bal',
      baseInput({ public_balance: '999' }),
      'REJECT',
      'INSUFFICIENT_BALANCE'
    );
    // Boundary semantics — the circuit is the referee, so these also validate
    // that our >= / < / <= choices match the circuit exactly.
    await runTaskCase(port, 'boundary balance == minimum', 'gk_bnd_bal', baseInput({ public_balance: '1000' }), 'APPROVE', 'OK');
    await runTaskCase(port, 'boundary amount == max', 'gk_bnd_amt', baseInput({ amount: '1000' }), 'APPROVE', 'OK');
    await runTaskCase(
      port,
      'boundary current == expiry - 1',
      'gk_bnd_blk1',
      baseInput({ current_block: 8429999 }),
      'APPROVE',
      'OK'
    );
    await runTaskCase(
      port,
      'boundary current == expiry',
      'gk_bnd_blk2',
      baseInput({ current_block: 8430000 }),
      'REJECT',
      'EXPIRED'
    );
    // Numeric task_id path.
    await runTaskCase(port, 'numeric task_id', '42', baseInput(), 'APPROVE', 'OK');

    // --- determinism: identical task -> identical public signals ---
    if (rValid) {
      const rValid2 = await post(port, taskEnvelope('gk_8d31f2a9c4', baseInput()));
      const sameSignals =
        JSON.stringify(rValid.body.public_signals) === JSON.stringify(rValid2.body.public_signals);
      check('determinism: same task -> identical public signals', sameSignals);
      // Groth16 proofs are randomized by design (blinding factors), so the
      // proof BYTES differ run to run. What must hold is that the replay
      // proof is also valid.
      let secondVerifies = false;
      try {
        secondVerifies = await snarkjs.groth16.verify(
          VKEY,
          rValid2.body.public_signals,
          rValid2.body.proof
        );
      } catch {
        secondVerifies = false;
      }
      check('determinism: replay proof also verifies', secondVerifies === true);
    }
  } finally {
    server.close();
  }

  const failed = results.filter((r) => !r.ok);
  const taskTimes = timings.map((t) => t.ms);
  const maxMs = Math.max(...taskTimes);
  console.log('\n================ SUMMARY ================');
  console.log(`checks: ${results.length - failed.length}/${results.length} passed`);
  console.log(`task end-to-end wall time: min ${Math.min(...taskTimes)}ms, max ${maxMs}ms`);
  console.log(`Vercel Hobby limit: 10000ms — headroom on slowest task: ${10000 - maxMs}ms`);
  if (failed.length > 0) {
    console.log('\nFAILED CHECKS:');
    for (const f of failed) console.log(`  - ${f.name} ${f.detail}`);
    process.exit(1);
  }
  console.log('ALL CHECKS PASSED');
  process.exit(0);
}

main().catch((e) => {
  console.error('HARNESS CRASHED:', e);
  process.exit(1);
});
