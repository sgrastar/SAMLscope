<?php
/** Isolated public native builder calibration. No hosted metadata/configuration is changed. */
require '/var/simplesamlphp/lib/_autoload.php';
try {
    $raw = stream_get_contents(STDIN);
    $input = json_decode($raw,true,512,JSON_THROW_ON_ERROR);
    $mode = $argv[1] ?? '';
    $source = $argv[2] ?? '';
    if (!in_array($mode,['stock-native-builder','developer-omitted-transport-key'],true)
        || !preg_match('/^[a-f0-9]{64}$/D',$source)
        || ($input['schema']??'')!=='samlscope-native-publisher-detector-input-v1'
        || ($input['purpose']??'')!=='oracle-calibration-only'
        || ($input['entityId']??'')!=='http://localhost:18380/idp') throw new \RuntimeException('Invalid public detector input');
    $metadata = ['entityid'=>$input['entityId'],'metadata-set'=>'saml20-idp-hosted',
                 'SingleSignOnService'=>$input['SingleSignOnService'],
                 'SingleLogoutService'=>$input['SingleLogoutService'],'keys'=>[]];
    $transport = 0;
    foreach ($input['roleKeys'] as $row) {
        $purpose = $row['purpose'] ?? ''; $encoded = $row['certificateDerBase64'] ?? '';
        if (!in_array($purpose,['signing','encryption','transport-authentication'],true)
            || !is_string($encoded) || base64_decode($encoded,true)===false) throw new \RuntimeException('Invalid public key input');
        if ($purpose==='transport-authentication') {
            ++$transport;
            if ($mode==='developer-omitted-transport-key') continue;
        }
        $metadata['keys'][] = ['type'=>'X509Certificate','X509Certificate'=>$encoded,
            'signing'=>$purpose!=='encryption','encryption'=>$purpose==='encryption'];
    }
    if ($transport!==1) throw new \RuntimeException('Exactly one detector transport key required');
    $builder = new \SimpleSAML\Metadata\SAMLBuilder($input['entityId']);
    $builder->addMetadataIdP20($metadata);
    $xml = $builder->getEntityDescriptorText();
    $loaded = [];
    foreach (['native-builder.php'=>\SimpleSAML\Metadata\SAMLBuilder::class,
              'native-configuration.php'=>\SimpleSAML\Configuration::class] as $name=>$class) {
        $reflection = new \ReflectionClass($class); $file = $reflection->getFileName();
        $loaded[] = ['logicalFile'=>$name,'class'=>$class,'file'=>$file,'sha256'=>hash_file('sha256',$file)];
    }
    echo json_encode(['schema'=>'samlscope-ssp-native-publisher-detector-output-v1','purpose'=>'oracle-calibration-only',
        'selectedProducer'=>$mode,'inputSha256'=>hash('sha256',$raw),'producerSourceSha256'=>$source,
        'metadataXmlBase64'=>base64_encode($xml),'metadataSha256'=>hash('sha256',$xml),'loadedClasses'=>$loaded,
        'productSettings'=>0,'samlSubmissions'=>0,'credentialPosts'=>0,'personOperations'=>0],
        JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES),"\n";
} catch (\Throwable $failure) {
    echo json_encode(['schema'=>'samlscope-ssp-native-publisher-detector-error-v1','exceptionClass'=>get_class($failure)]),"\n";
    exit(2);
}
