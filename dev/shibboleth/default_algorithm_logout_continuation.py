"""Follow only the native SLO page's same-flow completion iframe.

This is browser navigation emitted by the stock target, not another SAML submission.
The Webflow execution value remains in memory and must never be saved in originals.
"""
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit
import hashlib

SLO_PATH = '/idp/profile/SAML2/POST/SLO'


class Iframes(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.sources = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'iframe':
            values = dict(attrs)
            self.sources.append(values.get('src'))


def continuation(response_url, page, status):
    current = urlsplit(response_url)
    if status != 200 or current.scheme != 'http' or current.netloc != 'localhost:18280' or current.path != SLO_PATH:
        return None
    parser = Iframes()
    parser.feed(page)
    if not parser.sources:
        return None
    if len(parser.sources) != 1 or not isinstance(parser.sources[0], str):
        raise ValueError('Native logout completion iframe is ambiguous')
    destination = urljoin(response_url, parser.sources[0])
    chosen = urlsplit(destination)
    fields = parse_qsl(chosen.query, keep_blank_values=True)
    if (chosen.scheme, chosen.netloc, chosen.path) != (current.scheme, current.netloc, SLO_PATH) or chosen.fragment:
        raise ValueError('Native logout continuation escaped the selected endpoint')
    if len(fields) != 2 or len(set(key for key, _ in fields)) != 2 or set(key for key, _ in fields) != {'execution', '_eventId'}:
        raise ValueError('Unexpected native logout continuation fields')
    values = dict(fields)
    if values['_eventId'] != 'proceed' or not values['execution'] or len(values['execution']) > 128:
        raise ValueError('Native logout completion event is not proven')
    active = [value for key, value in parse_qsl(current.query, keep_blank_values=True) if key == 'execution']
    if active and active != [values['execution']]:
        raise ValueError('Native logout completion belongs to a different flow')
    return destination


def public_response_identity(response_url):
    """Public URL projection, with the exact URL bound by hash if Webflow state is present."""
    parsed = urlsplit(response_url)
    fields = parse_qsl(parsed.query, keep_blank_values=True)
    if any(key == 'execution' for key, _ in fields):
        return {'responseUrl': urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', '')),
                'responseUrlSha256': hashlib.sha256(response_url.encode()).hexdigest(),
                'responseUrlQueryRedacted': True}
    return {'responseUrl': response_url, 'responseUrlQueryRedacted': False}
