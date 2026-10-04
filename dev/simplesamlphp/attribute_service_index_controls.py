#!/usr/bin/env python3
"""Native signature-valid attribute-selection calibration; no target protocol sends."""
import argparse,json,subprocess,hashlib
from pathlib import Path
from attribute_service_index_campaign import CONTAINER,inspect_identity,save,sha
PRODUCER=r'''
require '/var/simplesamlphp/lib/_autoload.php';$input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
$d=\SAML2\DOMDocumentFactory::fromString($input['response']);$xp=new DOMXPath($d);$xp->registerNamespace('s','urn:oasis:names:tc:SAML:2.0:assertion');$xp->registerNamespace('d','http://www.w3.org/2000/09/xmldsig#');
foreach(iterator_to_array($xp->query('//d:Signature')) as $n)$n->parentNode->removeChild($n);
$a=$xp->query('//s:Assertion')->item(0);$statement=$xp->query('./s:AttributeStatement',$a)->item(0);if($statement===null)throw new \RuntimeException('Missing original attributes');while($statement->firstChild!==null)$statement->removeChild($statement->firstChild);
$kind=$input['kind'];if($kind==='correct-index-one'){$name='urn:oid:2.5.4.4';$value='samlscope-reference-surname';}elseif($kind==='wrong-index-one'){$name='urn:oid:0.9.2342.19200300.100.1.1';$value=$input['uid'];}elseif($kind==='wrong-index-zero'){$name='urn:oid:2.5.4.4';$value='samlscope-reference-surname';}else throw new \RuntimeException('Unknown control');
$n=$d->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion','saml:Attribute');$n->setAttribute('Name',$name);$n->setAttribute('NameFormat','urn:oasis:names:tc:SAML:2.0:attrname-format:uri');$v=$d->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion','saml:AttributeValue');$v->nodeValue=$value;$n->appendChild($v);$statement->appendChild($n);
$key=new \RobRichards\XMLSecLibs\XMLSecurityKey(\RobRichards\XMLSecLibs\XMLSecurityKey::RSA_SHA256,['type'=>'private']);$key->loadKey('/var/simplesamlphp/cert/server.pem',true);$cert=file_get_contents('/var/simplesamlphp/cert/server.crt');
\SAML2\Utils::insertSignature($key,[$cert],$a,$a->firstChild->nextSibling);$r=$d->documentElement;$status=$r->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol','Status')->item(0);\SAML2\Utils::insertSignature($key,[$cert],$r,$status);echo $d->saveXML();
'''
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);a=p.parse_args();out=a.folder.resolve();controls=out/'producer-controls';controls.mkdir(exist_ok=False)
 assert inspect_identity()==json.loads((out/'identity-after.json').read_text());(controls/'native-producer-command.php').write_text(PRODUCER);(controls/'collector.py').write_bytes(Path(__file__).read_bytes());records=[]
 for kind,index in [('correct-index-one',1),('wrong-index-one',1),('wrong-index-zero',0)]:
  flow=json.loads((out/('index-'+str(index))/'flow.json').read_text());ref=flow['positive_exchange']['transcript_ids'][-1];raw=(out/'decoded'/(ref+'.xml')).read_bytes();uid=json.loads((out/'control-after/session.json').read_text())['uid'][0]
  r=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',PRODUCER],input=json.dumps(dict(response=raw.decode(),uid=uid,kind=kind)).encode(),capture_output=True,timeout=30)
  if r.returncode:raise ValueError('Native producer failed')
  (controls/(kind+'.xml')).write_bytes(r.stdout);records.append(dict(kind=kind,index=index,baseResponseReference=ref,baseResponseSha256=sha(raw),controlSha256=sha(r.stdout)))
 save(controls/'manifest.json',dict(runId=json.loads((out/'created.json').read_text())['run']['id'],records=records,nativeProducerInvocations=3,productConfigurationWrites=0,protocolSends=0,humanOperations=0,nativeIdentityUnchanged=inspect_identity()==json.loads((out/'identity-after.json').read_text())))
if __name__=='__main__':main()
