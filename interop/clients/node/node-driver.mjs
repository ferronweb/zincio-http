// Interop driver built on Node's stdlib http2.
//
// Usage:
//   node client.mjs BASE_URL PROTOCOL SCENARIO [key=value ...]
//
// Prints one observation line per request on stdout:
//   status=<u16> len=<n> sha=<hex|-> trailers=<0|1> hints=<0|1> err=<text>
//
// Node connects with h2c prior knowledge for http: URLs, so no TLS setup is
// needed. Trailers surface through the 'trailers' event; informational
// responses through 'response' with a 1xx :status, when the runtime delivers
// them.

'use strict';
const http2 = require('http2');
const crypto = require('crypto');

const REQUEST_TIMEOUT_MS = 60000;
const ABORT_AFTER = 64 * 1024;

function pattern(n) {
  const out = Buffer.alloc(n);
  const p = Buffer.from('ABCD');
  for (let i = 0; i < n; i++) out[i] = p[i % 4];
  return out;
}

function emit(status, length, digest, trailers, hints, err = '') {
  const sha = digest ? digest : '-';
  console.log(
    `status=${status} len=${length} sha=${sha} ` +
    `trailers=${trailers ? 1 : 0} hints=${hints ? 1 : 0} err=${err}`
  );
}

function openSession(baseUrl) {
  return new Promise((resolve, reject) => {
    const client = http2.connect(baseUrl);
    client.on('error', reject);
    client.once('connect', () => resolve(client));
    setTimeout(() => reject(new Error('connect_timeout')), 10000);
  });
}

function doRequest(client, method, path, upload, extra, deadline) {
  return new Promise((resolve) => {
    const headers = {
      ':method': method,
      ':path': path,
      'x-interop': '1',
      ...extra,
    };
    const req = client.request(headers);
    let status = 0;
    const chunks = [];
    let trailers = false;
    let hints = false;
    let done = false;
    const finish = (err) => {
      if (done) return;
      done = true;
      if (err) {
        resolve({ status: 0, body: Buffer.alloc(0), trailers: false, hints: false, error: err });
        return;
      }
      const body = Buffer.concat(chunks);
      const digest = crypto.createHash('sha256').update(body).digest('hex');
      resolve({ status, body, digest, trailers, hints, error: null });
    };
    const timer = setTimeout(() => {
      req.close(http2.constants.NGHTTP2_CANCEL);
      finish('timeout');
    }, Math.max(1000, deadline - Date.now()));
    const clear = () => clearTimeout(timer);

    req.on('response', (headers) => {
      const code = parseInt(headers[':status'], 10);
      if (code === 103) {
        hints = true;
      } else if (!isNaN(code)) {
        status = code;
      }
    });
    req.on('trailers', (trailersHeaders) => {
      if (trailersHeaders['x-echo-trailer'] !== undefined) trailers = true;
    });
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => { clear(); finish(null); });
    req.on('error', (e) => { clear(); finish(e.code || 'stream_error'); });
    req.on('close', () => { clear(); finish('closed'); });

    if (upload && upload.length > 0) {
      req.end(upload);
    } else {
      req.end();
    }
  });
}

async function runScenario(baseUrl, scenario, params) {
  const method = params.method || 'GET';
  let path = params.path || '/small';
  const uploadLen = parseInt(params.upload_len || '0', 10) || 0;
  const upload = uploadLen > 0 ? pattern(uploadLen) : null;
  const deadline = Date.now() + REQUEST_TIMEOUT_MS;

  const extra = {};
  if (scenario === 'many_headers') {
    for (let i = 0; i < 200; i++) {
      extra[`x-interop-${String(i).padStart(4, '0')}`] = 'v';
    }
  } else if (scenario === 'big_header_rejected') {
    extra['x-big'] = 'v'.repeat(32 * 1024);
  } else if (scenario === 'long_uri') {
    path += '?' + pattern(8 * 1024).toString();
  } else if (scenario === 'expect_continue') {
    extra['expect'] = '100-continue';
  }

  if (scenario === 'concurrency') {
    const count = parseInt(params.count || '32', 10) || 32;
    const client = await openSession(baseUrl);
    try {
      const results = await Promise.all(
        Array.from({ length: count }, () =>
          doRequest(client, 'GET', path, null, {}, deadline)
        )
      );
      for (const r of results) {
        if (r.error) emit(0, 0, '', false, false, r.error);
        else emit(r.status, r.body.length, r.digest, r.trailers, r.hints);
      }
    } finally {
      client.close();
    }
    return;
  }

  if (scenario === 'abort_midstream') {
    const client = await openSession(baseUrl);
    try {
      // Open a large stream, read partway, then cancel it.
      const headers = { ':method': 'GET', ':path': path, 'x-interop': '1' };
      const req = client.request(headers);
      let received = 0;
      await new Promise((resolve) => {
        const timer = setTimeout(resolve, 30000);
        req.on('data', (chunk) => {
          received += chunk.length;
          if (received >= ABORT_AFTER) {
            clearTimeout(timer);
            req.close(http2.constants.NGHTTP2_CANCEL);
            resolve();
          }
        });
        req.on('end', () => { clearTimeout(timer); resolve(); });
        req.on('error', () => { clearTimeout(timer); resolve(); });
        req.end();
      });
      const follow = await doRequest(client, 'GET', '/small', null, {}, deadline);
      if (follow.error) emit(0, 0, '', false, false, follow.error);
      else emit(follow.status, follow.body.length, follow.digest, follow.trailers, follow.hints);
    } finally {
      client.close();
    }
    return;
  }

  if (scenario === 'idle_reuse') {
    const idleMs = parseInt(params.idle_ms || '3000', 10) || 3000;
    await new Promise((r) => setTimeout(r, idleMs));
    const client = await openSession(baseUrl);
    try {
      const r = await doRequest(client, method, path, upload, extra, deadline);
      if (r.error) emit(0, 0, '', false, false, r.error);
      else emit(r.status, r.body.length, r.digest, r.trailers, r.hints);
    } finally {
      client.close();
    }
    return;
  }

  const client = await openSession(baseUrl);
  try {
    const r = await doRequest(client, method, path, upload, extra, deadline);
    if (r.error) emit(0, 0, '', false, false, r.error);
    else emit(r.status, r.body.length, r.digest, r.trailers, r.hints);
  } finally {
    client.close();
  }
}

async function main(argv) {
  if (argv[0] === '--selftest') {
    try {
      require('http2');
      return 0;
    } catch {
      return 1;
    }
  }
  if (argv.length === 0) {
    console.log('interop-driver ready');
    // Idle mode: the container's main process. A bare never-resolving promise
    // does not keep Node alive (no active handles), so park on a real timer.
    setInterval(() => {}, 3600_000);
    await new Promise(() => {});
  }
  const [baseUrl, , scenario, ...rest] = argv;
  const params = {};
  for (const item of rest) {
    const eq = item.indexOf('=');
    if (eq >= 0) params[item.slice(0, eq)] = item.slice(eq + 1);
  }
  try {
    await runScenario(baseUrl, scenario, params);
  } catch (e) {
    emit(0, 0, '', false, false, (e && e.code) || 'failed');
  }
  return 0;
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  () => process.exit(1)
);
