<?php
/** Public native default-policy projection. Secrets and credentials never leave native memory. */
function samlscope_public_peer_metadata(array $values): array {
    $public=[];
    foreach (['entityid','metadata-set','metadata-index'] as $field) {
        if (array_key_exists($field,$values)) {
            if (!is_string($values[$field])) throw new RuntimeException('Invalid public identifier');
            $public[$field]=$values[$field];
        }
    }
    foreach (['validate.authnrequest','redirect.validate','sign.authnrequest','sign.logout','redirect.sign','saml20.sign.assertion'] as $field) {
        if (array_key_exists($field,$values)) {
            if (!is_bool($values[$field])) throw new RuntimeException('Invalid public policy');
            $public[$field]=$values[$field];
        }
    }
    if (array_key_exists('expire',$values)) {
        if (!is_int($values['expire'])) throw new RuntimeException('Invalid public expiry');
        $public['expire']=$values['expire'];
    }
    if (array_key_exists('contacts',$values)) {
        // The dedicated Suite fixture has no ContactPerson entries. Other forms stay unqualified.
        if ($values['contacts']!==[]) throw new RuntimeException('Unsupported public contacts');
        $public['contacts']=[];
    }
    foreach (['AssertionConsumerService','SingleLogoutService','ArtifactResolutionService'] as $field) {
        if (!array_key_exists($field,$values)) continue;
        if (!is_array($values[$field])) throw new RuntimeException('Invalid public endpoint');
        $public[$field]=[];
        foreach ($values[$field] as $endpoint) {
            if (!is_array($endpoint)) throw new RuntimeException('Invalid public endpoint');
            $row=[];
            foreach (['Binding','Location','ResponseLocation'] as $part) {
                if (array_key_exists($part,$endpoint)) {
                    if (!is_string($endpoint[$part])) throw new RuntimeException('Invalid public endpoint value');
                    $row[$part]=$endpoint[$part];
                }
            }
            foreach (['index','isDefault'] as $part) {
                if (array_key_exists($part,$endpoint)) {
                    if (($part==='index' && !is_int($endpoint[$part])) || ($part==='isDefault' && !is_bool($endpoint[$part])))
                        throw new RuntimeException('Invalid public endpoint flag');
                    $row[$part]=$endpoint[$part];
                }
            }
            $public[$field][]=$row;
        }
    }
    if (array_key_exists('NameIDFormat',$values)) {
        $formats=$values['NameIDFormat'];
        if (is_string($formats)) $public['NameIDFormat']=$formats;
        elseif (is_array($formats) && array_is_list($formats) && count(array_filter($formats,'is_string'))===count($formats))
            $public['NameIDFormat']=$formats;
        else throw new RuntimeException('Invalid public identifier format');
    }
    if (array_key_exists('keys',$values)) {
        if (!is_array($values['keys'])) throw new RuntimeException('Invalid public key list');
        $public['keys']=[];
        foreach ($values['keys'] as $key) {
            if (!is_array($key) || ($key['type']??null)!=='X509Certificate' || !is_string($key['X509Certificate']??null))
                throw new RuntimeException('Unsupported public key form');
            $der=base64_decode($key['X509Certificate'],true);
            if ($der===false || openssl_x509_read("-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($der),64,"\n")."-----END CERTIFICATE-----\n")===false)
                throw new RuntimeException('Invalid public certificate');
            $row=['type'=>'X509Certificate','X509Certificate'=>$key['X509Certificate']];
            foreach (['signing','encryption'] as $part) {
                if (array_key_exists($part,$key)) {
                    if (!is_bool($key[$part])) throw new RuntimeException('Invalid public key use');
                    $row[$part]=$key[$part];
                }
            }
            $public['keys'][]=$row;
        }
    }
    return $public;
}
function samlscope_public_metadata_sources(array $values): array {
    $public=[];
    foreach ($values as $value) {
        if (!is_array($value) || !in_array($value['type']??null,['flatfile','serialize','mdq','mdx','pdo'],true))
            throw new RuntimeException('Unsupported native metadata source');
        $public[]=['type'=>$value['type']];
    }
    return $public;
}
// Native collection starts here. Projection tests execute only the functions above.
ini_set('display_errors','0');
try {
    require '/var/simplesamlphp/lib/_autoload.php';
    $input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
    $entity=$input['entity'];$metadata=[];require '/var/simplesamlphp/metadata/saml20-sp-remote.php';
    $handler=\SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();
    $idp=$handler->getMetaDataConfig('http://localhost:18380/idp','saml20-idp-hosted');
    $present=isset($metadata[$entity]);$peer=['present'=>$present];
    if ($present) {
        $native=$handler->getMetaDataConfig($entity,'saml20-sp-remote');$resolved=$native->toArray();
        $peer+=['resolvedMetadata'=>samlscope_public_peer_metadata($resolved),
            'resolvedMetadataSha256'=>hash('sha256',json_encode($resolved,JSON_THROW_ON_ERROR)),
            'validateAuthnRequest'=>$native->getOptionalBoolean('validate.authnrequest',null),
            'redirectValidate'=>$native->getOptionalBoolean('redirect.validate',null)];
        unset($resolved);
    }
    $hashes=[];foreach ($input['sourcePaths'] as $name=>$path) $hashes[$name]=hash_file('sha256',$path);
    $sources=\SimpleSAML\Configuration::getInstance()->getArray('metadata.sources');
    echo json_encode(['peer'=>$peer,'remoteConfigurationSha256'=>hash_file('sha256','/var/simplesamlphp/metadata/saml20-sp-remote.php'),
        'metadataSources'=>samlscope_public_metadata_sources($sources),
        'metadataSourceConfigurationSha256'=>array_map(static fn(array $source):string=>hash('sha256',serialize($source)),$sources),
        'sourceHashes'=>$hashes,'defaultPolicy'=>[
            'hostedValidateAuthnRequest'=>$idp->getOptionalBoolean('validate.authnrequest',null),
            'hostedRedirectValidate'=>$idp->getOptionalBoolean('redirect.validate',null),
            'globalConfigurationSha256'=>hash_file('sha256','/var/simplesamlphp/config/config.php'),
            'hostedConfigurationSha256'=>hash_file('sha256','/var/simplesamlphp/metadata/saml20-idp-hosted.php'),
            'authenticationConfigurationSha256'=>hash_file('sha256','/var/simplesamlphp/config/authsources.php'),
            'autoPrependFile'=>ini_get('auto_prepend_file'),'autoAppendFile'=>ini_get('auto_append_file'),'opcachePreload'=>ini_get('opcache.preload')]],JSON_THROW_ON_ERROR);
} catch (\Throwable $failure) {
    // Native exception text may contain credentials; emit no native message or stack.
    echo json_encode(['schema'=>'samlscope-ssp-default-policy-state-error-v1','exceptionClass'=>get_class($failure)]),"\n";
    exit(2);
}
