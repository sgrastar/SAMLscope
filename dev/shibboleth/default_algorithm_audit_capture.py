"""Contemporaneous public audit-byte capture; an empty capture is never a decision."""
import hashlib,re

PREFIX='SAMLscope-default-algorithm-v1|'
PATH='/opt/reference-idp/logs/idp-audit.log'
SHA=lambda b:hashlib.sha256(b).hexdigest()

def capture(run,request_id,request_sha,fixture,before,after,delta):
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run) or not re.fullmatch(r'_[A-Za-z0-9_-]+',request_id):
        raise ValueError('Audit capture identity invalid')
    if not re.fullmatch(r'[0-9a-f]{64}',request_sha):raise ValueError('Audit capture request hash invalid')
    if (before['inode']!=after['inode'] or before['size']<0 or after['size']-before['size']!=len(delta)):
        raise ValueError('Audit byte range changed or incomplete')
    if re.search(rb'(?i)authorization\s*:|cookie\s*:|(?:j_)?password\s*[:=]',delta):
        raise ValueError('Private audit capture refused')
    lines=[line for line in delta.decode('utf-8').splitlines() if line.strip()]
    matching=[line for line in lines if line.startswith(PREFIX) and line.split('|')[1]==request_id]
    # A different request, duplicate audit, or unrecognized formatter is uncertain.
    if len(matching)>1 or lines!=matching:raise ValueError('Audit operation range ambiguous')
    early=fixture=='rsa-md5' and not matching and not delta
    if not matching and not early:raise ValueError('Native operation audit missing')
    value=dict(schema='samlscope-shibboleth-native-audit-capture-v1',runId=run,
        requestId=request_id,requestSha256=request_sha,path=PATH,inode=before['inode'],
        beforeOffset=before['size'],afterOffset=after['size'],beforeCapturedAt=before['capturedAt'],
        afterCapturedAt=after['capturedAt'],deltaBytes=len(delta),deltaSha256=SHA(delta),
        matchingAuditCount=len(matching),decisionEvidence=False)
    return value,(matching[0]+'\n').encode() if matching else None
