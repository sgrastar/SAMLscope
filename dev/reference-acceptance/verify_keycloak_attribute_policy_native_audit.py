#!/usr/bin/env python3
"""Replay the read-only Keycloak attribute-policy import audit; never adopt a verdict."""
import copy
import hashlib
import json
from pathlib import Path

IMAGE = "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067"
CONVERTER = "f12ac7fc23ddaec03f2b0d61c47368dae8038b478a4972a66d0ff7f3415de4ec"
UID = "urn:oid:0.9.2342.19200300.100.1.1"
SURNAME = "urn:oid:2.5.4.4"
ORDER = ["baseline.xml", "entity-present.xml", "entity-absent.xml",
         "requested-required.xml", "requested-optional.xml", "requested-absent.xml", "indexed.xml"]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(value, message="invalid Keycloak native attribute-policy audit"):
    if not value:
        raise ValueError(message)


def mapper(record, name):
    return next((item for item in record["protocolMappers"] if item["name"] == name), None)


def verify_records(records):
    require([record["fixture"] for record in records] == ORDER)
    require(all(record["converterCodeSource"].endswith("/org.keycloak.keycloak-services-26.7.2.jar")
                for record in records))
    by_name = {record["fixture"]: record for record in records}
    common_attribute_keys = set(by_name["baseline.xml"]["attributes"])
    require(all(set(record["attributes"]) == common_attribute_keys for record in records))
    require(not any("entity" in key.lower() or "requested" in key.lower()
                    or "consuming" in key.lower() for key in common_attribute_keys))
    for name in ("baseline.xml", "entity-present.xml", "entity-absent.xml", "requested-absent.xml"):
        require(by_name[name]["protocolMappers"] == [])
    required = mapper(by_name["requested-required.xml"], UID)
    optional = mapper(by_name["requested-optional.xml"], UID)
    require(required is not None and required == optional)
    require(required["config"] == {"attribute.name": UID, "attribute.nameformat": "URI Reference"})
    indexed = by_name["indexed.xml"]["protocolMappers"]
    require({item["name"] for item in indexed} == {UID, SURNAME})
    require(all(set(item["config"]) == {"attribute.name", "attribute.nameformat"} for item in indexed))
    require(not any("required" in json.dumps(item).lower() or "index" in json.dumps(item).lower()
                    for record in records for item in record["protocolMappers"]))
    return {"entityAttributesPreserved": False, "isRequiredPreserved": False,
            "attributeConsumingServiceIndexPreserved": False}


def verify(root, tamper=False):
    root = Path(root).resolve()
    image = json.loads((root / "image-inspect.json").read_text())[0]
    container = json.loads((root / "container-inspect.json").read_text())[0]
    require(image["Id"] == container["Image"] == IMAGE)
    require(image["RepoDigests"] == ["quay.io/keycloak/keycloak@" + IMAGE])
    require(container["Config"]["Image"] == "quay.io/keycloak/keycloak@" + IMAGE)
    converter = root / "product-originals/EntityDescriptorDescriptionConverter.class"
    require(sha(converter) == CONVERTER)
    bytecode = (root / "product-originals/EntityDescriptorDescriptionConverter.javap").read_text()
    require("getAttributeConsumingService" in bytecode and "getRequestedAttribute" in bytecode)
    require("isIsRequired" not in bytecode and "EntityAttributes" not in bytecode)
    records = json.loads((root / "native-converter-output.json").read_text())
    conclusion = verify_records(records)
    mutations = []
    if tamper:
        variants = {
            "entity": lambda x: x[1]["protocolMappers"].append({"name": "forged"}),
            "required": lambda x: x[3]["protocolMappers"][0]["config"].update(required="true"),
            "index": lambda x: x[6]["protocolMappers"][0]["config"].update(index="0"),
            "drop": lambda x: x.pop(),
        }
        for name, mutate in variants.items():
            candidate = copy.deepcopy(records)
            mutate(candidate)
            try:
                verify_records(candidate)
            except ValueError:
                mutations.append(name)
            else:
                raise AssertionError("audit mutation accepted: " + name)
    fixtures = {path.name: sha(path) for path in sorted((root / "fixtures").glob("*.xml"))}
    report = {"schema": "samlscope-keycloak-native-attribute-policy-audit-v1",
        "productImage": IMAGE, "converterClassSha256": CONVERTER,
        "converterOutputSha256": sha(root / "native-converter-output.json"),
        "fixtureSha256": fixtures, "conclusion": conclusion,
        "adoptedCases": [], "remainingCases": ["IIP-IDP03-a-idp-01", "IIP-IDP04-a-idp-01",
            "IIP-IDP04-b-idp-01"], "reason": "approved-configuration-precondition-unavailable",
        "operations": {"productConfigurationWrites": 0, "productRestarts": 0,
            "protocolRoundTrips": 0, "humanOperations": 0, "nativeConverterInvocations": 1},
        "tamperRejections": mutations}
    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--tamper", action="store_true")
    args = parser.parse_args()
    report = verify(args.root, args.tamper)
    (args.root / "audit-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
