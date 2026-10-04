#!/usr/bin/env python3
"""Compare the native PDP parser with and without a foreign attribute; no verdicts.

No product settings or implementation files are changed. The signed historical XML is
preserved, while derived parser-only controls remove the Signature before changing XML.
This separates a role-parser precondition failure from foreign-attribute handling.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("ssp_native_metadata_import", Path(__file__).with_name("import_metadata_batch.py"))
native_import = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native_import)
CONTAINER, PHP = native_import.CONTAINER, native_import.PHP

MD = "urn:oasis:names:tc:SAML:2.0:metadata"
DS = "http://www.w3.org/2000/09/xmldsig#"
FOREIGN = "urn:samlscope:fixture:foreign-attribute"
SOURCE = "/var/simplesamlphp/vendor/simplesamlphp/saml2-legacy/src/SAML2/XML/md/PDPDescriptor.php"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def state():
    return {
        "runtime": subprocess.check_output(
            ["docker", "inspect", "--format", "{{.Id}} {{.Image}} {{.State.StartedAt}} {{.State.Running}}", CONTAINER],
            timeout=30, text=True).strip(),
        "configuration": subprocess.check_output(
            ["docker", "exec", CONTAINER, "sha256sum", "/var/simplesamlphp/metadata/saml20-sp-remote.php"],
            timeout=30, text=True).strip(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    before = state()
    write(out / "state-before.json", before)
    source = subprocess.check_output(["docker", "exec", CONTAINER, "cat", SOURCE], timeout=30)
    (out / "native-PDPDescriptor.php").write_bytes(source)
    records = []
    try:
        for profile in ("browser_sso_idp", "ecp_idp", "metadata_idp", "single_logout_idp"):
            folder = out / profile
            folder.mkdir()
            historical = REPO / "build/acceptance/reference-20260930/ext01c-simplesamlphp-v159" / profile / "metadata/foreign-attribute-authz/fixture.xml"
            original = historical.read_bytes()
            (folder / "signed-historical-fixture.xml").write_bytes(original)
            root = ET.fromstring(original)
            entity = root.attrib["entityID"]
            for parent in root.iter():
                for child in list(parent):
                    if child.tag == "{" + DS + "}Signature":
                        parent.remove(child)
            pdp = root.find("{" + MD + "}PDPDescriptor")
            endpoint = pdp.find("{" + MD + "}AuthzService") if pdp is not None else None
            if endpoint is None or "{" + FOREIGN + "}undefined" not in endpoint.attrib:
                raise ValueError("Historical foreign AuthzService original unavailable")
            native_inputs = [("foreign-attribute-present", ET.tostring(root))]
            endpoint.attrib.pop("{" + FOREIGN + "}undefined")
            native_inputs.append(("foreign-attribute-absent", ET.tostring(root)))
            root.remove(pdp)
            native_inputs.append(("pdp-role-absent-control", ET.tostring(root)))
            for label, xml in native_inputs:
                (folder / (label + ".xml")).write_bytes(xml)
                result = subprocess.run(["docker", "exec", "-i", CONTAINER, "php", "-r", PHP, entity, "default"],
                    input=xml, capture_output=True, timeout=30)
                (folder / (label + ".stdout")).write_bytes(result.stdout)
                (folder / (label + ".stderr")).write_bytes(result.stderr)
                records.append({"profile": profile, "control": label, "originalSha256": sha(original),
                    "inputSha256": sha(xml), "stdoutSha256": sha(result.stdout),
                    "stderrSha256": sha(result.stderr), "returncode": result.returncode})
        for profile in ("browser_sso_idp", "ecp_idp", "metadata_idp", "single_logout_idp"):
            members = {r["control"]: r for r in records if r["profile"] == profile}
            if not (members["foreign-attribute-present"]["returncode"] != 0
                    and members["foreign-attribute-absent"]["returncode"] != 0
                    and members["pdp-role-absent-control"]["returncode"] == 0):
                raise ValueError("Native PDP precondition diagnosis did not reproduce")
            for label in ("foreign-attribute-present", "foreign-attribute-absent"):
                if "Must have at least one AuthzService in PDPDescriptor" not in (out / profile / (label + ".stderr")).read_text():
                    raise ValueError("Native failure differs from the historical blocker")
    finally:
        after = state()
        write(out / "state-after.json", after)
        write(out / "operations.json", records)
        write(out / "summary.json", {"schema": "samlscope-pdp-parser-precondition-audit-v1",
            "sourcePath": SOURCE, "sourceSha256": sha(source), "parserCommandSha256": sha(PHP.encode()),
            "parserInvocations": len(records), "configurationWrites": 0, "productRestarts": 0,
            "protocolOperations": 0, "humanOperations": 0, "configurationUnchanged": before == after,
            "verdictAdopted": False, "diagnosis": "native-pdp-precondition-fails-with-and-without-foreign-attribute"})
        if before != after:
            raise ValueError("Product state changed during read-only parser audit")
    print("Native PDP precondition reproduced across four profiles; no verdict changed")


if __name__ == "__main__":
    main()
