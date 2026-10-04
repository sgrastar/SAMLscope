<?php
/** Native converter output is used intact; no optional policy field is deleted or fabricated. */
require '/var/simplesamlphp/lib/_autoload.php';
$xml=stream_get_contents(STDIN);(new \SimpleSAML\Utils\XML())->checkSAMLMessage($xml,'saml-meta');
$entities=\SimpleSAML\Metadata\SAMLParser::parseDescriptorsString($xml);
if(count($entities)!==1)throw new RuntimeException('One native entity required');
$entity=array_key_first($entities);$metadata=$entities[$entity]->getMetadata20SP();
if($metadata===null)throw new RuntimeException('Native SP role absent');
echo json_encode(['entityId'=>$entity,'fixtureSha256'=>hash('sha256',$xml),'metadata'=>$metadata,
 'php'=>'$metadata['.var_export($entity,true).'] = '.var_export($metadata,true).';'],JSON_THROW_ON_ERROR);
