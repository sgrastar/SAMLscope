<?php
/** Public metadata/input diagnostics. No private key, HTTP, or configuration mutation. */
require '/var/simplesamlphp/lib/_autoload.php';
$input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
$xml=base64_decode($input['metadata'],true);
if ($xml===false) {throw new RuntimeException('Public metadata encoding invalid');}
(new \SimpleSAML\Utils\XML())->checkSAMLMessage($xml,'saml-meta');
$parsed=\SimpleSAML\Metadata\SAMLParser::parseDescriptorsString($xml);
if (count($parsed)!==1) {throw new RuntimeException('One public native peer required');}
$entity=array_key_first($parsed);$remote=$parsed[$entity]->getMetadata20SP();
if ($remote===null || array_key_exists('validate.authnrequest',$remote)) {
    throw new RuntimeException('Factory did not preserve the native default signing declaration');
}
$source=\SimpleSAML\Configuration::loadFromArray($remote,'public-default-consumer-diagnostic');
$handler=\SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();
$hosted=$handler->getMetaDataConfig('http://localhost:18380/idp','saml20-idp-hosted');
$rows=[];
foreach($input['inputs'] as $fixture=>$encoded) {
    $raw=base64_decode($encoded,true);if($raw===false) {throw new RuntimeException('Public input encoding invalid');}
    $dom=new DOMDocument();$dom->loadXML($raw,LIBXML_NONET);
    $request=new \SAML2\AuthnRequest($dom->documentElement);
    $row=['fixture'=>$fixture,'inputSha256'=>hash('sha256',$raw),'requestId'=>$request->getId(),
        'issuer'=>$request->getIssuer()->getValue(),'constructedSignature'=>$request->isMessageConstructedWithSignature()];
    try {
        $validated=\SimpleSAML\Module\saml\Message::validateMessage($source,$hosted,$request);
        $row['nativeSignatureGate']=$validated?'VALIDATED':'SKIPPED';
    } catch(Throwable $error) {
        $row['nativeSignatureGate']='REJECTED';$row['exceptionClass']=get_class($error);
        // Exception messages can contain arbitrary native values; do not export them.
    }
    $rows[]=$row;
}
$classes=[];
foreach(['SimpleSAML\Metadata\SAMLParser','SimpleSAML\Module\saml\Message','SAML2\Message',
        'SAML2\Utils','RobRichards\XMLSecLibs\XMLSecurityDSig','RobRichards\XMLSecLibs\XMLSecurityKey'] as $name) {
    $r=new ReflectionClass($name);$classes[]=['class'=>$name,'path'=>$r->getFileName(),'sha256'=>hash_file('sha256',$r->getFileName())];
}
echo json_encode(['schema'=>'samlscope-ssp-default-consumer-native-api-diagnostic-v1','recordedAt'=>gmdate('c'),
    'runId'=>$input['runId'],'planId'=>$input['planId'],'metadataSha256'=>hash('sha256',$xml),
    'nativeParserValidateAuthnRequest'=>$source->getOptionalBoolean('validate.authnrequest',null),
    'nativeParserRedirectValidate'=>$source->getOptionalBoolean('redirect.validate',null),
    'hostedValidateAuthnRequest'=>$hosted->getOptionalBoolean('validate.authnrequest',null),
    'hostedRedirectValidate'=>$hosted->getOptionalBoolean('redirect.validate',null),
    'rows'=>$rows,'classes'=>$classes,'configurationWrites'=>0,'targetHttp'=>0,'credentialPosts'=>0,
    'actualMd5CryptoVerificationClaimed'=>false,'actualProductFinding'=>false],JSON_THROW_ON_ERROR);
