"""Remove native authentication-state parameters before any public HTML persistence."""
import re
from consent_ui_campaign import sanitized as hidden_projection
PARAMETER=re.compile(r'((?:StateId|AuthState)(?:=|%3[Dd]))[^\s\"\'<>]*',re.I)
NONCE=re.compile(r'_[0-9a-f]{40}',re.I)
def sanitized(page,stateId=None):
    projected=hidden_projection(page,stateId)
    return parameters_only(projected)
def parameters_only(projected):
    projected=PARAMETER.sub(lambda match:match.group(1)+'[REDACTED]',projected)
    # The state value can be HTML-escaped, URL-escaped, or present in a native link's
    # nested return URL. Its opaque identifier is never useful to a conformance oracle.
    projected=NONCE.sub('[REDACTED-NATIVE-STATE]',projected)
    return projected
def contains_state_secret(page):
    return NONCE.search(page) is not None or any('[REDACTED]' not in m.group(0) for m in PARAMETER.finditer(page))
