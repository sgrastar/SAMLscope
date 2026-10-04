#!/usr/bin/env python3
"""Public signed expiry-ignore oracle calibration; never sends or records SAML."""
import argparse, hashlib, json, subprocess
from pathlib import Path
import xml.etree.ElementTree as ET

PRODUCER = r'''
require '/var/simplesamlphp/lib/_autoload.php';
$input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
$document=\SAML2\DOMDocumentFactory::fromString($input['response']);
$request=\SAML2\DOMDocumentFactory::fromString($input['request'])->documentElement;
$xp=new DOMXPath($document);$xp->registerNamespace('s','urn:oasis:names:tc:SAML:2.0:assertion');$xp->registerNamespace('d','http://www.w3.org/2000/09/xmldsig#');
foreach(iterator_to_array($xp->query('//d:Signature')) as $signature)$signature->parentNode->removeChild($signature);
$response=$document->documentElement;$response->setAttribute('IssueInstant',$request->getAttribute('IssueInstant'));$response->setAttribute('InResponseTo',$request->getAttribute('ID'));$response->setAttribute('Destination',$request->getAttribute('AssertionConsumerServiceURL'));
foreach(iterator_to_array($xp->query('//s:SubjectConfirmationData')) as $data){$data->setAttribute('InResponseTo',$request->getAttribute('ID'));$data->setAttribute('Recipient',$request->getAttribute('AssertionConsumerServiceURL'));}
$key=new \RobRichards\XMLSecLibs\XMLSecurityKey(\RobRichards\XMLSecLibs\XMLSecurityKey::RSA_SHA256,['type'=>'private']);$key->loadKey('/var/simplesamlphp/cert/server.pem',true);
$certificate=file_get_contents('/var/simplesamlphp/cert/server.crt');$assertion=$xp->query('//s:Assertion')->item(0);$assertion->setAttribute('IssueInstant',$request->getAttribute('IssueInstant'));$subject=$xp->query('./s:Subject',$assertion)->item(0);
\SAML2\Utils::insertSignature($key,[$certificate],$assertion,$subject);$status=$response->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol','Status')->item(0);\SAML2\Utils::insertSignature($key,[$certificate],$response,$status);
echo $document->saveXML();
'''

def sha(raw): return hashlib.sha256(raw).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);args=p.parse_args();root=args.folder.resolve();out=root/'calibration';out.mkdir(exist_ok=False)
    manifest=json.loads((root/'receipt/manifest.json').read_text());decoded={r['id']:root/r['file'] for r in json.loads((root/'decoded-manifest.json').read_text())};row=manifest['observations'][1]
    response=decoded[row['before']['responseReference']].read_bytes();request=decoded[row['after']['requestReference']].read_bytes()
    (out/'producer.php').write_text(PRODUCER)
    result=subprocess.run(['docker','exec','-i','samlscope-reference-ssp','php','-r',PRODUCER],input=json.dumps({'response':response.decode(),'request':request.decode()}).encode(),capture_output=True,timeout=40)
    if result.returncode: raise RuntimeError('Native public-only calibration signer failed: '+str(result.returncode))
    signed=result.stdout;ET.fromstring(signed);(out/'earlier-parent-expiry-ignore.xml').write_bytes(signed)
    record=dict(purpose='diagnostic-oracle-calibration-only',mutant='earlier-parent-expiry-ignore',runId=manifest['runId'],originalResponseSha256=sha(response),originalRequestSha256=sha(request),producerSha256=sha(PRODUCER.encode()),signedXmlSha256=sha(signed),nativeCliSignerInvocations=1,productConfigurationWrites=0,protocolSubmissions=0,personOperations=0,privateMaterialExported=False,recordedIntoRun=False)
    (out/'calibration.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record))

if __name__=='__main__': main()
