'use strict';
// HMAC-SHA256 helpers for the Agent Games protocol.
// Header: x-agent-games-signature = hex(HMAC-SHA256(secret, rawBody))
// Applies to inbound requests (verified BEFORE parsing) and outbound
// responses (signed over the exact bytes sent).
const crypto = require('crypto');

function signHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function verifyHex(secret, rawBody, signatureHex) {
  if (typeof signatureHex !== 'string' || !signatureHex) return false;
  let sig = signatureHex.trim().toLowerCase();
  // Tolerate a "sha256=" prefix (GitHub-style) if the platform ever adds one.
  if (sig.startsWith('sha256=')) sig = sig.slice('sha256='.length);
  if (!/^[0-9a-f]{64}$/.test(sig)) return false;
  const expected = signHex(secret, rawBody);
  return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(sig, 'hex'));
}

module.exports = { signHex, verifyHex };
