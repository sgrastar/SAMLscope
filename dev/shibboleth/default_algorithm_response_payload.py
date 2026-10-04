"""Locate actual Redirect response bytes without rebuilding its signed query."""
import base64
import hashlib
import urllib.parse
import xml.etree.ElementTree as ET
import zlib

P = "urn:oasis:names:tc:SAML:2.0:protocol"
LIMIT = 2_097_152


def require(value, reason):
    if not value:
        raise ValueError(reason)


def redirect_response(url):
    require(isinstance(url, str) and len(url) <= LIMIT, "Unbounded response URL")
    parsed = urllib.parse.urlsplit(url)
    fields = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=64)
    responses = [value for key, value in fields if key == "SAMLResponse"]
    if not responses:
        return None
    require(len(responses) == 1 and not any(key == "SAMLRequest" for key, _ in fields),
            "Ambiguous Redirect response payload")
    require(parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.fragment
            and parsed.username is None and parsed.password is None, "Unsafe response URL")
    compressed = base64.b64decode(responses[0], validate=True)
    require(len(compressed) <= LIMIT, "Unbounded compressed response")
    inflater = zlib.decompressobj(-15)
    raw = inflater.decompress(compressed, LIMIT + 1)
    require(len(raw) <= LIMIT and not inflater.unconsumed_tail and inflater.eof
            and not inflater.unused_data, "Incomplete or unbounded Redirect response")
    require(b"<!DOCTYPE" not in raw and b"<!ENTITY" not in raw, "Unsafe Redirect XML")
    root = ET.fromstring(raw)
    require(root.tag in {f"{{{P}}}Response", f"{{{P}}}LogoutResponse"}, "Unexpected response kind")
    # This is an input locator. The production reader independently verifies the
    # untouched raw query signature and ties these bytes to the Recorder original.
    return {"responseSamlSha256": hashlib.sha256(raw).hexdigest(),
            "responseSamlBytes": len(raw), "responseBinding": "HTTP-Redirect",
            "responseRawQuerySha256": hashlib.sha256(parsed.query.encode("ascii")).hexdigest()}
