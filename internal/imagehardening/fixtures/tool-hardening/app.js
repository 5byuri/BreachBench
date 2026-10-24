// Public synthetic offline fixture: test real loopback HTTP, then allow profiling to finish.
'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');

const server = http.createServer((request, response) => {
  response.setHeader('Content-Type', 'application/json');
  if (request.url === '/health') {
    response.end(JSON.stringify({ status: 'healthy' }));
  } else if (request.url === '/hello?name=world') {
    response.end(JSON.stringify({ message: 'hello world' }));
  } else {
    response.statusCode = 404;
    response.end(JSON.stringify({ error: 'not found' }));
  }
});

(async () => {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  for (const [path, expected] of [['/health', { status: 'healthy' }], ['/hello?name=world', { message: 'hello world' }]]) {
    const response = await fetch(origin + path);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), expected);
  }
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  console.log('PUBLIC_NODE_HTTP_SELFTEST_OK');
  await new Promise(resolve => setTimeout(resolve, 12000));
})().catch(error => {
  server.close();
  console.error(error.message);
  process.exitCode = 1;
});
