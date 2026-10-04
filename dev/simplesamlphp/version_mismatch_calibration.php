<?php
/** Public detector calibration. This never sends a SAML message or changes the stock product. */
require '/var/simplesamlphp/lib/_autoload.php';
use RobRichards\XMLSecLibs\XMLSecurityKey;
$input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
if(($input['schema']??null)!=='samlscope-version-status-calibration-input-v1'
    ||!preg_match('/^run_[0-9A-HJKMNP-TV-Z]{26}$/D',$input['runId']??''))throw new RuntimeException('Bound public input required');
$key=new XMLSecurityKey(XMLSecurityKey::RSA_SHA256,['type'=>'private']);$key->loadKey('/var/simplesamlphp/cert/server.pem',true);
$certificate=file_get_contents('/var/simplesamlphp/cert/server.crt');$controls=[];
if(count($input['controls']??[])!==3)throw new RuntimeException('Exactly three non-adopted controls required');
$seen=[];
foreach($input['controls'] as $row){
 foreach(['fixtureId','requestId','destination','issuer','status'] as $field)if(!is_string($row[$field]??null)||$row[$field]==='')throw new RuntimeException('Missing public field');
 if(!in_array($row['fixtureId'],['version-1-1-satisfied','version-1-1-mutant','nonversion-wrong-code'],true)||isset($seen[$row['fixtureId']]))throw new RuntimeException('Unknown/duplicate diagnostic');
 $seen[$row['fixtureId']]=true;
 $expected=['version-1-1-satisfied'=>'VersionMismatch','version-1-1-mutant'=>'Requester','nonversion-wrong-code'=>'VersionMismatch'];
 if($row['status']!==$expected[$row['fixtureId']])throw new RuntimeException('Diagnostic control semantics changed');
 if($row['issuer']!=='http://localhost:18380/idp'||!preg_match('/^_action_[0-9a-f]+$/D',$row['requestId']))throw new RuntimeException('Wrong native issuer/request');
 $doc=new DOMDocument();$root=$doc->createElementNS('urn:oasis:names:tc:SAML:2.0:protocol','p:Response');$doc->appendChild($root);
 $root->setAttribute('ID','_diagnostic_'.hash('sha256',$row['fixtureId'].$input['runId']));$root->setAttribute('Version','2.0');$root->setAttribute('InResponseTo',$row['requestId']);$root->setAttribute('Destination',$row['destination']);
 $root->setAttribute('IssueInstant',gmdate('Y-m-d\TH:i:s\Z'));
 $issuer=$doc->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion','s:Issuer');$issuer->appendChild($doc->createTextNode($row['issuer']));$root->appendChild($issuer);
 $status=$doc->createElementNS('urn:oasis:names:tc:SAML:2.0:protocol','p:Status');$code=$doc->createElementNS('urn:oasis:names:tc:SAML:2.0:protocol','p:StatusCode');$code->setAttribute('Value','urn:oasis:names:tc:SAML:2.0:status:'.$row['status']);$status->appendChild($code);$root->appendChild($status);
 \SAML2\Utils::insertSignature($key,[$certificate],$root,$status);
 $raw=$doc->saveXML();$controls[]=['fixtureId'=>$row['fixtureId'],'requestId'=>$row['requestId'],'responseBase64'=>base64_encode($raw),'sha256'=>hash('sha256',$raw)];
}
echo json_encode(['schema'=>'samlscope-version-status-calibration-output-v1','runId'=>$input['runId'],'controls'=>$controls,'counterfactualCalibrationOnly'=>true,'controlsAdopted'=>false,'nativePrivateKeyExported'=>false,'sourceSha256'=>hash_file('sha256',__FILE__),'nativeUtilsSha256'=>hash_file('sha256','/var/simplesamlphp/vendor/simplesamlphp/saml2-legacy/src/SAML2/Utils.php'),'productSettings'=>0,'protocolSubmissions'=>0,'credentialPosts'=>0],JSON_THROW_ON_ERROR);
