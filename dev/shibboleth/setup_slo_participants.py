"""Register two extra Suite SP participants for the logout propagation harness.

The Suite records an inbound LogoutRequest only on its own SLO routes (/p/{plan}/sp/slo and
/p/{plan}/sp/slo/soap, correlated by the run query parameter). The failing participant points at
the /sp/slo-fail fixture so the target's propagation attempt is induced as an HTTP 500; the
remaining participant points at the recorded front-channel route so the target's continuation
after the failure is captured.
"""
import subprocess
import sys
import xml.etree.ElementTree as E

plan = 'plan_3C0PZPNZD8P9C1MXK9V9QJ43DD'
run = sys.argv[1]


def call(*args):
    return subprocess.check_output(['docker', *args], stderr=subprocess.STDOUT).decode().strip()


path = '/opt/reference-idp/metadata/suite.xml'
root = E.fromstring(call('exec', 'samlscope-reference-shibboleth', 'cat', path))
ns = 'urn:oasis:names:tc:SAML:2.0:metadata'
ds = 'http://www.w3.org/2000/09/xmldsig#'


def q(tag):
    return '{' + ns + '}' + tag


entry = next(x for x in root.iter() if x.get('entityID') == f'http://localhost:18080/p/{plan}')
primary_sp = entry.find(q('SPSSODescriptor'))
keys = list(primary_sp.findall(q('KeyDescriptor')))
key = keys[0] if keys else None
acs = primary_sp.find(q('AssertionConsumerService'))
acs_location = acs.get('Location') if acs is not None else f'http://localhost:18080/p/{plan}/sp/acs/0'
for x in list(root):
    if x.get('entityID', '').endswith('/sp-fail') or x.get('entityID', '').endswith('/sp-remain'):
        root.remove(x)


def entity(entity_id, soap_location, front_location):
    e = E.Element(q('EntityDescriptor'))
    e.set('ID', '_' + entity_id.split('/')[-1])
    e.set('entityID', entity_id)
    sp = E.SubElement(e, q('SPSSODescriptor'))
    sp.set('protocolSupportEnumeration', 'urn:oasis:names:tc:SAML:2.0:protocol')
    sp.set('AuthnRequestsSigned', 'false')
    sp.set('WantAssertionsSigned', 'true')
    for k in keys:
        sp.append(E.fromstring(E.tostring(k)))
    base = 'urn:oasis:names:tc:SAML:2.0:bindings:'
    for binding, loc in (('SOAP', soap_location), ('HTTP-POST', front_location), ('HTTP-Redirect', front_location)):
        s = E.SubElement(sp, q('SingleLogoutService'))
        s.set('Binding', base + binding)
        s.set('Location', loc)
    a = E.SubElement(sp, q('AssertionConsumerService'))
    a.set('Binding', base + 'HTTP-POST')
    a.set('Location', acs_location)
    a.set('index', '0')
    a.set('isDefault', 'true')
    return e


root.append(entity(f'http://localhost:18080/p/{plan}/sp-fail',
                   f'http://localhost:18080/p/{plan}/sp/slo-fail?run={run}',
                   f'http://localhost:18080/p/{plan}/sp/slo-fail?run={run}'))
root.append(entity(f'http://localhost:18080/p/{plan}/sp-remain',
                   f'http://localhost:18080/p/{plan}/sp/slo/soap?run={run}',
                   f'http://localhost:18080/p/{plan}/sp/slo?run={run}'))
subprocess.run(['docker', 'exec', '-i', 'samlscope-reference-shibboleth', 'sh', '-c', 'cat > ' + path],
               input=E.tostring(root), check=True)
subprocess.run(['docker', 'exec', 'samlscope-reference-shibboleth', '/opt/reference-idp/bin/reload-service.sh',
                '-id', 'shibboleth.MetadataResolverService', '-u', 'http://localhost:8080/idp'],
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
print('participants registered for run', run)
