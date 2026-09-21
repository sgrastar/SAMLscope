"""Pure native audit-format transformation, independent of product driver imports."""
import xml.etree.ElementTree as ET

B='http://www.springframework.org/schema/beans'
U='http://www.springframework.org/schema/util'
FORMAT='SAMLscope-signature-v1|%I|%SP|%e|%S|%XX|%b|%P|%T'


def signature_audit(original):
    root=ET.fromstring(original)
    maps=[n for n in root if n.tag=='{'+U+'}map' and n.get('id')=='shibboleth.AuditFormattingMap']
    if len(maps)!=1:raise ValueError('Ambiguous native audit map')
    entries=[n for n in maps[0] if n.tag=='{'+B+'}entry' and n.get('key')=='Shibboleth-Audit']
    if len(entries)!=1:raise ValueError('Ambiguous native audit format')
    entries[0].set('value',FORMAT)
    return ET.tostring(root,encoding='utf-8',xml_declaration=True)
