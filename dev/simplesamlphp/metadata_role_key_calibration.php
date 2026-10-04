<?php
/** Counterfactual detector fixtures only. Native private key remains inside this product process. */
require '/var/simplesamlphp/lib/_autoload.php';
use RobRichards\XMLSecLibs\XMLSecurityKey;
$input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
$key=new XMLSecurityKey(XMLSecurityKey::RSA_SHA256,['type'=>'private']);$key->loadKey('/var/simplesamlphp/cert/server.pem',true);
$certificate=file_get_contents('/var/simplesamlphp/cert/server.crt');
$esc=static fn(string $s):string=>htmlspecialchars($s,ENT_QUOTES|ENT_XML1,'UTF-8');$controls=[];
if(count($input['controls'])!==6)throw new RuntimeException('Exactly six counterfactual controls required');
foreach($input['controls'] as $row){
 foreach(['issuer','entity','requestId','recipient','instant','fixtureId'] as $name)if(!is_string($row[$name]??null)||$row[$name]==='')throw new RuntimeException('Missing public input');
 if($row['issuer']!=='http://localhost:18380/idp')throw new RuntimeException('Wrong native target');
 $now=$esc($row['instant']);$until=$esc((new DateTimeImmutable($row['instant']))->modify('+5 minutes')->format('Y-m-d\TH:i:s.u\Z'));
 $issuer=$esc($row['issuer']);$entity=$esc($row['entity']);$request=$esc($row['requestId']);$recipient=$esc($row['recipient']);
 $xml="<p:Response xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:s='urn:oasis:names:tc:SAML:2.0:assertion' ID='_role_key_calibration_response' Version='2.0' IssueInstant='$now' InResponseTo='$request' Destination='$recipient'><s:Issuer>$issuer</s:Issuer><p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status><s:Assertion ID='_role_key_calibration_assertion' Version='2.0' IssueInstant='$now'><s:Issuer>$issuer</s:Issuer><s:Subject><s:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'>synthetic-role-key-mutant-subject</s:NameID><s:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'><s:SubjectConfirmationData InResponseTo='$request' Recipient='$recipient' NotOnOrAfter='$until'/></s:SubjectConfirmation></s:Subject><s:Conditions NotBefore='$now' NotOnOrAfter='$until'><s:AudienceRestriction><s:Audience>$entity</s:Audience></s:AudienceRestriction></s:Conditions><s:AuthnStatement AuthnInstant='$now' SessionIndex='synthetic-role-key-mutant-session'><s:AuthnContext><s:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</s:AuthnContextClassRef></s:AuthnContext></s:AuthnStatement></s:Assertion></p:Response>";
 $doc=new DOMDocument();if(!$doc->loadXML($xml,LIBXML_NONET))throw new RuntimeException('Invalid public detector input');
 $assertion=$doc->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion','Assertion')->item(0);
 \SAML2\Utils::insertSignature($key,[$certificate],$assertion,$assertion->firstChild->nextSibling);
 \SAML2\Utils::insertSignature($key,[$certificate],$doc->documentElement,$doc->documentElement->firstChild->nextSibling);
 $raw=$doc->saveXML();$controls[]=['fixtureId'=>$row['fixtureId'],'requestId'=>$row['requestId'],'responseBase64'=>base64_encode($raw),'sha256'=>hash('sha256',$raw)];
}
echo json_encode(['schema'=>'samlscope-simplesamlphp-metadata-role-key-calibration-v1','controls'=>$controls,'nativePrivateKeyExported'=>false,'controlsAdopted'=>false,'counterfactualCalibrationOnly'=>true,'sourceSha256'=>hash_file('sha256',__FILE__),'nativeUtilsSha256'=>hash_file('sha256','/var/simplesamlphp/vendor/simplesamlphp/saml2-legacy/src/SAML2/Utils.php'),'productConfigurationWrites'=>0,'protocolOperations'=>0,'productRestarts'=>0,'humanOperations'=>0],JSON_THROW_ON_ERROR);
