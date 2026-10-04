#!/usr/bin/env python3
"""Export a Run-bound public trust proof by reusing immutable native role-key originals."""
import argparse,hashlib,json,pathlib,os
REPO=pathlib.Path(__file__).resolve().parents[2];SHA=lambda b:hashlib.sha256(b).hexdigest();LOAD=lambda p:json.loads(p.read_bytes())
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();source=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True);assert (out/'calibration/stock-native-output.json').is_file();receipt=out/'receipt';receipt.mkdir(exist_ok=False);binding={}
 for name in ['created.json','target-metadata.xml','transcript.json','decoded-manifest.json']:
  os.link(source/name,out/name);binding[name]=SHA((source/name).read_bytes())
 originals=out/'source-role';originals.mkdir();
 for name in ['created.json','target-metadata.xml','transcript.json','decoded-manifest.json']:
  os.link(source/name,originals/name)
 for name in ['receipt','decoded']:
  dest=originals/name;dest.mkdir()
  for file in (source/name).iterdir():assert file.is_file() and not file.is_symlink();os.link(file,dest/file.name)
 for name in ['self_contained_trust_calibration.php','stock-input.json','stock-native-output.json','mutant-input.json','mutant-native-output.json','operations.json']:os.link(out/'calibration'/name,receipt/name)
 m=LOAD(source/'receipt/manifest.json');target=LOAD(out/'created.json')['run'];assert m['runId']==target['id'];native=LOAD(receipt/'stock-native-output.json');assert native['runId']==target['id'] and native['mutantControlsAdopted'] is False and native['counterfactualCalibrationOnly'] is False
 value=dict(schema='samlscope-simplesamlphp-self-contained-trust-v1',adapter='simplesamlphp-native-self-contained-trust-v1',caseId='IIP-MD06-c-idp-01',runId=target['id'],campaignId='native-metadata-trust',targetMetadataSha256=m['targetMetadataSha256'],targetEntityId='http://localhost:18380/idp',peerEntityId=m['entityId'],roleReceiptSha256=SHA((source/'receipt/manifest.json').read_bytes()),selectedPath='stock-native-signature-encryption',counterfactualCalibrationOnly=False)
 for field,file in [('producer','self_contained_trust_calibration.php'),('input','stock-input.json'),('nativeOutput','stock-native-output.json'),('operations','operations.json')]:value[field+'File']=file;value[field+'Sha256']=SHA((receipt/file).read_bytes())
 (out/'trust-receipt.json').write_text(json.dumps(value,indent=2)+'\n');(out/'source-binding.json').write_text(json.dumps(dict(folder=source.name,files=binding,roleReceiptSha256=value['roleReceiptSha256'],sourceOperationsReusedNotNew=True),indent=2)+'\n');print(target['id'],'public metadata trust proof exported')
if __name__=='__main__':main()
