"""Native Shibboleth comparison fixtures. These configure an explicit local ordering, not universal method strengths."""
import re
import xml.etree.ElementTree as ET

B = 'http://www.springframework.org/schema/beans'
U = 'http://www.springframework.org/schema/util'
RANKS = ('low', 'medium', 'high')


def reference(kind, rank):
    return 'urn:samlscope:reference:authn:' + kind.lower() + ':' + rank


def inputs():
    result = []
    for case, comparison in [('ga', 'MINIMUM'), ('gb', 'BETTER'), ('gc', 'MAXIMUM'), ('gj', 'EXACT')]:
        for kind in ['CLASS', 'DECLARATION']:
            prefix = 'class' if kind == 'CLASS' else 'declaration'
            if case == 'gj':
                conditions = [('forward', ['low', 'high']), ('reverse', ['high', 'low'])]
            else:
                conditions = [('selection', ['high' if case == 'gc' else 'low']), ('unachievable', ['unavailable'])]
            for condition, values in conditions:
                result.append(dict(id=f'{case}-{prefix}-{condition}', kind=kind, comparison=comparison,
                                   references=[reference(kind, value) for value in values]))
    for kind in ['CLASS', 'DECLARATION']:
        prefix = 'class' if kind == 'CLASS' else 'declaration'
        for rank in ['low', 'medium']:
            result.append(dict(id=f'control-{prefix}-{rank}', kind=kind, comparison='EXACT', references=[reference(kind, rank)]))
    return result


def configure(comparison_xml, authn_properties, maximum=False):
    root = ET.fromstring(comparison_xml)
    if root.tag != '{' + B + '}beans':
        raise ValueError('Unexpected native comparison configuration')
    if any(node.get('id') == 'shibboleth.AuthnComparisonRules' for node in root):
        raise ValueError('Existing comparison rules require explicit adaptation')
    rules = ET.SubElement(root, '{' + U + '}map', {'id': 'shibboleth.AuthnComparisonRules'})
    for kind, bean_kind in [('CLASS', 'Class'), ('DECLARATION', 'Decl')]:
        for comparison in ['Minimum', 'Better', 'Maximum']:
            entry = ET.SubElement(rules, '{' + B + '}entry', {'key-ref': 'shibboleth.SAMLAC' + bean_kind + 'Ref' + comparison})
            bean = ET.SubElement(entry, '{' + B + '}bean', {'parent': 'shibboleth.InexactMatchFactory'})
            prop = ET.SubElement(bean, '{' + B + '}property', {'name': 'matchingRules'})
            mapping = ET.SubElement(prop, '{' + B + '}map')
            for rank in [*RANKS, 'unavailable']:
                item = ET.SubElement(mapping, '{' + B + '}entry', {'key': reference(kind, rank)})
                values = ET.SubElement(item, '{' + B + '}list')
                if rank == 'unavailable':
                    continue
                threshold = RANKS.index(rank)
                selected = [name for index, name in enumerate(RANKS)
                            if (index >= threshold if comparison == 'Minimum' else
                                index > threshold if comparison == 'Better' else index <= threshold)]
                for value in selected:
                    ET.SubElement(values, '{' + B + '}value').text = reference(kind, value)
    text = authn_properties.decode()
    if re.search(r'^\s*idp.authn.Password.supportedPrincipals\s*[=:]', text, re.M):
        raise ValueError('Existing Password principal override requires explicit adaptation')
    principals = []
    for kind, type_name in [('CLASS', 'saml2'), ('DECLARATION', 'saml2declref')]:
        principals.extend(type_name + '/' + reference(kind, rank) for rank in (RANKS[:2] if maximum else RANKS))
    text += '\n# Temporary SAMLscope native comparison experiment; restored after collection.\n'
    text += 'idp.authn.Password.supportedPrincipals = ' + ', '.join(principals) + '\n'
    return ET.tostring(root, encoding='utf-8', xml_declaration=True), text.encode()
