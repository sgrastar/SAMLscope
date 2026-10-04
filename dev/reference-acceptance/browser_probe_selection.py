"""Prepare unselected Suite probes without sending their requests to the target."""
import re
import urllib.error
import urllib.parse
import urllib.request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def selected_cases(value):
    if value is None:
        return None
    result = {item.strip() for item in value.split(',')}
    if not result or any(re.fullmatch(r'IIP-[A-Za-z0-9]+-[A-Za-z0-9]+-idp-01', case) is None
                         for case in result):
        raise ValueError('Invalid selected case list')
    return result


def prepare_and_skip(base, run, status, api):
    """Abort only this prepared action; redirects and HTML never submit a target request."""
    start = urllib.parse.urlsplit(status['startUrl'])
    expected = urllib.parse.urlsplit(base)
    if (status.get('state') != 'READY' or not status.get('actionId') or not status.get('caseId')
            or start.scheme not in {'http', 'https'}
            or (start.scheme, start.netloc) != (expected.scheme, expected.netloc)
            or start.username is not None or start.password is not None or start.fragment
            or re.fullmatch(r'/p/[^/]+/probe/[^/]+', start.path) is None
            or urllib.parse.unquote(start.path.rsplit('/', 1)[1]) != status['actionId']
            or urllib.parse.parse_qs(start.query).get('run') != [run]):
        raise ValueError('Unselected preparation URL/action is not the Suite')
    opener = urllib.request.build_opener(_NoRedirect())
    request = urllib.request.Request(status['startUrl'],
        data=urllib.parse.urlencode({'freshSessionConfirmed': 'true'}).encode(),
        headers={'Content-Type': 'application/x-www-form-urlencoded'}, method='POST')
    try:
        with opener.open(request, timeout=30) as response:
            # Read a bounded page; no HTML form, script, or redirect is executed.
            response.read(1024 * 1024 + 1)
            code = response.status
    except urllib.error.HTTPError as response:
        try:
            if response.code not in {301, 302, 303, 307, 308}:
                raise
            response.read(1024 * 1024 + 1)
            code = response.code
        finally:
            response.close()
    path = '/api/runs/' + run + '/active-probe'
    after = api(path)
    if (after.get('actionId') != status['actionId'] or after.get('caseId') != status['caseId']
            or after.get('state') != 'AWAITING_RESPONSE'):
        raise RuntimeError('Unselected action was not prepared without submission')
    api(path + '/abort', {})
    return dict(caseId=status['caseId'], actionId=status['actionId'],
                action='prepared-and-skipped-before-target-submission', prepared=True,
                preparedHttpStatus=code, sentToTarget=False)
