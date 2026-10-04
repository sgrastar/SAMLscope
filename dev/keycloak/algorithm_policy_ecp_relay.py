"""Relay existing Suite outbox SOAP originals, with credentials retained only in memory.

The response to one fixture stays withheld until the next native policy has been
applied and read back. Thus the next outbox request is recorded after its policy.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import queue
import re
import threading
import urllib.error
import urllib.request as http

TARGET = "http://localhost:18180/realms/samlscope/protocol/saml"
SOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"


class Relay:
    def __init__(self, out, port):
        self.out = out
        self.queue = queue.Queue()
        self.pending = None
        self.exchanges = []
        self.probe_result = None
        self.probe_error = None
        self.probe_thread = None
        self.server = ThreadingHTTPServer(("0.0.0.0", port), self.handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        with http.urlopen(TARGET + "/descriptor", timeout=30) as response:
            raw = response.read()
        location = "http://host.docker.internal:" + str(port) + "/saml"
        pattern = rb'(<(?:[A-Za-z0-9_]+:)?SingleSignOnService\b[^>]*Binding="' + SOAP.encode() + rb'"[^>]*Location=")[^"]*(")'
        self.metadata, count = re.subn(pattern, lambda match: match[1] + location.encode() + match[2], raw)
        if count != 1:
            raise RuntimeError("SOAP metadata endpoint is not unique")
        (out / "target-metadata-overlay.xml").write_bytes(self.metadata)
        self.metadata_url = "http://host.docker.internal:" + str(port) + "/metadata"
        self.thread.start()

    def handler(self):
        relay = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                if self.path != "/metadata":
                    self.send_error(404); return
                self.send_response(200)
                self.send_header("Content-Type", "application/samlmetadata+xml")
                self.send_header("Content-Length", str(len(relay.metadata)))
                self.end_headers()
                self.wfile.write(relay.metadata)

            def do_POST(self):
                if self.path != "/saml":
                    self.send_error(404); return
                length = int(self.headers.get("Content-Length", "-1"))
                if not 0 < length <= 1_048_576:
                    self.send_error(413); return
                body = self.rfile.read(length)
                headers = {name: self.headers[name] for name in ("Authorization", "Content-Type", "Accept")
                           if self.headers.get(name)}
                if not headers.get("Authorization", "").startswith("Basic "):
                    self.send_error(401); return
                reply = queue.Queue()
                relay.queue.put((body, headers, reply))
                try:
                    status, raw, content_type = reply.get(timeout=100)
                    self.send_response(status)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                except Exception:
                    self.send_error(502)
        return Handler

    def start_probe(self, base, run, username, password):
        def execute():
            try:
                request = http.Request(base + "/api/runs/" + run + "/ecp-probe",
                    data=json.dumps(dict(username=username, password=password)).encode(),
                    headers={"Content-Type": "application/json"})
                with http.urlopen(request, timeout=240) as response:
                    self.probe_result = json.load(response)
            except Exception as error:
                self.probe_error = type(error).__name__ + ":" + str(error)
        self.probe_thread = threading.Thread(target=execute, daemon=True)
        self.probe_thread.start()

    def exchange(self, label, folder):
        self.flush()
        body, headers, reply = self.queue.get(timeout=35)
        request = http.Request(TARGET, data=body, headers=headers)
        try:
            with http.urlopen(request, timeout=35) as response:
                status, raw = response.status, response.read(1_048_577)
                content_type = response.headers.get("Content-Type", "text/xml")
        except urllib.error.HTTPError as response:
            status, raw = response.code, response.read(1_048_577)
            content_type = response.headers.get("Content-Type", "text/xml")
        if len(raw) > 1_048_576:
            raise RuntimeError("SOAP response too large")
        # The headers never become evidence. Only exact body originals survive.
        (folder / "relay-request.xml").write_bytes(body)
        (folder / "relay-response.xml").write_bytes(raw)
        row = dict(phase=label, status=status, requestSha256=hashlib.sha256(body).hexdigest(),
                   responseSha256=hashlib.sha256(raw).hexdigest(), targetUrl=TARGET,
                   credentialForwardedOnly=True, cookieForwarded=False)
        self.exchanges.append(row)
        self.pending = (reply, (status, raw, content_type))
        return "native-http-" + str(status), row

    def flush(self):
        if self.pending is not None:
            reply, result = self.pending
            reply.put(result)
            self.pending = None

    def finish(self):
        self.flush()
        if self.probe_thread is not None:
            self.probe_thread.join(timeout=40)
            if self.probe_thread.is_alive() or self.probe_error is not None:
                raise RuntimeError("ECP probe did not finish: " + str(self.probe_error))
        if len(self.exchanges) != 7:
            raise RuntimeError("Seven outbox ECP fixtures were not received")

    def stop(self):
        self.flush()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
