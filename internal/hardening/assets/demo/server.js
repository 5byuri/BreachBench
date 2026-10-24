'use strict';
const http = require('node:http');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

// Deliberate training vulnerability. Never deploy this application.
http.createServer(async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  if (req.method === 'GET' && req.url === '/health') return res.end('{"ok":true}');
  if (req.method !== 'POST' || req.url !== '/evaluate') {
    res.writeHead(404); return res.end('{}');
  }
  try {
    let body = '';
    for await (const chunk of req) {
      body += chunk;
      if (body.length > 8192) throw new Error('request too large');
    }
    const {code} = JSON.parse(body);
    const value = await new AsyncFunction('require', 'process', code)(require, process);
    res.end(JSON.stringify({ok: true, value}));
  } catch (error) {
    res.end(JSON.stringify({ok: false, error: error.code || error.message}));
  }
}).listen(Number(process.env.PORT || 3000), '127.0.0.1');
