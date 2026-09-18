#!/usr/bin/env node
/** Loopback-only HTTP/TLS delivery of one pre-generated public fixture image. */
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import crypto from 'node:crypto';

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  return index < 0 ? fallback : process.argv[index + 1];
}
const httpPort = Number(argument('--http-port', '18480'));
const httpsPort = Number(argument('--https-port', '18443'));
if (![httpPort, httpsPort].every(port => Number.isInteger(port) && port >= 1024 && port <= 65535)
    || httpPort === httpsPort) throw new Error('Distinct unprivileged ports required');
const asset = fs.readFileSync(argument('--asset'));
if (asset.length === 0 || asset.length > 65536) throw new Error('Invalid fixture image size');
const certificate = fs.readFileSync(argument('--certificate'));
const key = fs.readFileSync(argument('--key'));
const cert = new crypto.X509Certificate(certificate);
const spki = crypto.createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
const assetPath = '/metadata-lab/ui-fixture.svg';
const counts = { http: 0, https: 0 };
function handler(transport) {
  return (request, response) => {
    // No URLs, headers, credentials, request bodies or client addresses are logged.
    if (request.url !== assetPath || !['GET', 'HEAD'].includes(request.method)) {
      response.writeHead(404); response.end(); return;
    }
    counts[transport]++;
    response.writeHead(200, { 'Content-Type': 'image/svg+xml; charset=utf-8',
      'Content-Length': asset.length, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; sandbox" });
    response.end(request.method === 'HEAD' ? undefined : asset);
  };
}
const servers = [http.createServer(handler('http')), https.createServer({ key, cert: certificate }, handler('https'))];
const listen = (server, port) => new Promise((resolve, reject) => {
  server.once('error', reject); server.listen(port, '127.0.0.1', resolve);
});
let closing = false;
async function close() {
  if (closing) return;
  closing = true;
  await Promise.all(servers.map(server => new Promise(resolve => {
    server.close(resolve); server.closeAllConnections();
  })));
  console.log(JSON.stringify({ status: 'stopped', image_requests: counts }));
}
process.once('SIGINT', close);
process.once('SIGTERM', close);
try {
  await listen(servers[0], httpPort);
  await listen(servers[1], httpsPort);
  console.log(JSON.stringify({ status: 'ready', http: `http://localhost:${httpPort}${assetPath}`,
    https: `https://localhost:${httpsPort}${assetPath}`, asset_sha256: crypto.createHash('sha256').update(asset).digest('hex'),
    certificate_spki_sha256_base64: spki }));
} catch {
  await close();
  console.error('Local fixture transport startup failed');
  process.exitCode = 1;
}
