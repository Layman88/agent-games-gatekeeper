'use strict';
// Tiny local dev server for the agent handler (manual smoke tests only).
// Usage: AGENT_GAMES_HMAC_SECRET=test-secret node test/serve.js
// Then:  curl http://127.0.0.1:3000/api/agent
const http = require('http');
const handler = require('../api/agent');

const port = Number(process.env.PORT || 3000);
http
  .createServer((req, res) => handler(req, res))
  .listen(port, '127.0.0.1', () => {
    console.log(`gatekeeper agent listening on http://127.0.0.1:${port}/api/agent`);
    console.log(`secret set: ${Boolean(process.env.AGENT_GAMES_HMAC_SECRET)}`);
  });
