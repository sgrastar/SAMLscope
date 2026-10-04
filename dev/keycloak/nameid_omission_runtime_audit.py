#!/usr/bin/env python3
"""Snapshot installed Keycloak 26.7.2 NameID generation paths for independent replay."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import urllib.request as http
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from attribute_policy_capability_absence import product_token

CONTAINER = "samlscope-reference-keycloak"
IMAGE = "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067"
SERVICES = "lib/lib/main/org.keycloak.keycloak-services-26.7.2.jar"
SAML_CORE = "lib/lib/main/org.keycloak.keycloak-saml-core-26.7.2.jar"
ADMIN_UI = "lib/lib/main/org.keycloak.keycloak-admin-ui-26.7.2.jar"
CLASSES = {
    "SamlProtocol": (SERVICES, "org.keycloak.protocol.saml.SamlProtocol"),
    "SamlClient": (SERVICES, "org.keycloak.protocol.saml.SamlClient"),
    "SamlConfigAttributes": (SERVICES, "org.keycloak.protocol.saml.SamlConfigAttributes"),
    "SamlRepresentationAttributes": (SERVICES, "org.keycloak.protocol.saml.SamlRepresentationAttributes"),
    "SamlProtocolFactory": (SERVICES, "org.keycloak.protocol.saml.SamlProtocolFactory"),
    "NameIdMapperHelper": (SERVICES, "org.keycloak.protocol.saml.mappers.NameIdMapperHelper"),
    "UserAttributeNameIdMapper": (SERVICES, "org.keycloak.protocol.saml.mappers.UserAttributeNameIdMapper"),
    "SAMLAudienceProtocolMapper": (SERVICES, "org.keycloak.protocol.saml.mappers.SAMLAudienceProtocolMapper"),
    "SAMLAudienceResolveProtocolMapper": (SERVICES, "org.keycloak.protocol.saml.mappers.SAMLAudienceResolveProtocolMapper"),
    "AuthnContextClassRefMapper": (SERVICES, "org.keycloak.protocol.saml.mappers.AuthnContextClassRefMapper"),
    "SAML2LoginResponseBuilder": (SAML_CORE, "org.keycloak.saml.SAML2LoginResponseBuilder"),
    "SAML2Response": (SAML_CORE, "org.keycloak.saml.processing.api.saml.v2.response.SAML2Response"),
    "SamlSessionUtils": (SERVICES, "org.keycloak.protocol.saml.SamlSessionUtils"),
    "SamlAuthenticationPreprocessorSpi": (SERVICES,
        "org.keycloak.protocol.saml.preprocessor.SamlAuthenticationPreprocessorSpi"),
}
TERMS = (b"SAMLLoginResponseMapper", b"SAMLNameIdMapper")


def sha(raw): return hashlib.sha256(raw).hexdigest()
def write(path, data): path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def main(folder):
    folder = Path(folder).resolve()
    jars = folder / "runtime-lib"
    if not jars.is_dir(): raise RuntimeError("runtime JAR snapshot missing")
    inspect = json.loads(subprocess.check_output(["docker", "inspect", CONTAINER]))[0]
    if not inspect["State"]["Running"] or inspect["Image"] != IMAGE:
        raise RuntimeError("unexpected running product")
    for mount in inspect.get("Mounts", []):
        destination = mount.get("Destination", "").rstrip("/")
        for path in ("/opt/keycloak/lib", "/opt/keycloak/providers"):
            if path == destination or path.startswith(destination + "/"):
                raise RuntimeError("runtime paths covered by host mount")
    write(folder / "runtime-binding.json", {"containerId": inspect["Id"], "imageId": inspect["Image"],
        "startedAt": inspect["State"]["StartedAt"], "configImage": inspect["Config"]["Image"],
        "mounts": [{"destination": m.get("Destination"), "type": m.get("Type")}
            for m in inspect.get("Mounts", [])]})
    live = subprocess.check_output(["docker", "exec", CONTAINER, "sh", "-c",
        "find /opt/keycloak/lib -name '*.jar' -type f -exec sha256sum {} \\;"], timeout=120).decode()
    live_manifest = {}
    for row in live.splitlines():
        digest, path = row.split(None, 1)
        if not path.startswith("/opt/keycloak/lib/") or path in live_manifest:
            raise RuntimeError("bad live JAR inventory")
        live_manifest[path[len("/opt/keycloak/"):]] = digest
    copied = {}
    for jar in jars.rglob("*.jar"):
        key = "lib/" + str(jar.relative_to(jars))
        copied[key] = sha(jar.read_bytes())
    if copied != live_manifest or len(copied) != 471:
        raise RuntimeError("copied JARs differ from live product")
    write(folder / "runtime-jars.json", {"count": len(copied), "sha256": copied})
    provider_listing = subprocess.check_output(["docker", "exec", CONTAINER, "sh", "-c",
        "cd /opt/keycloak/providers && find . -type f -print | LC_ALL=C sort"]).decode().splitlines()
    if provider_listing != ["./README.md"]: raise RuntimeError("unexpected custom provider")
    write(folder / "providers.json", {"files": provider_listing})

    token = product_token()
    with http.urlopen(http.Request("http://localhost:18180/admin/serverinfo",
            headers={"Authorization": "Bearer " + token}), timeout=30) as response:
        server = json.load(response)
    mappers = server.get("protocolMapperTypes", {}).get("saml")
    providers = server.get("providers", {})
    if not isinstance(mappers, list): raise RuntimeError("SAML mapper schema missing")
    write(folder / "serverinfo-nameid.json", {
        "mappers": mappers,
        "clientPolicyExecutors": providers.get("client-policy-executor"),
        "scripting": providers.get("scripting"),
        "loginProtocol": providers.get("login-protocol"),
        "samlAuthenticationPreprocessor": providers.get("saml-authentication-preprocessor"),
    })
    for path in ("/client-policies/policies", "/client-policies/profiles"):
        with http.urlopen(http.Request("http://localhost:18180/admin/realms/samlscope" + path,
                headers={"Authorization": "Bearer " + token}), timeout=30) as response:
            value = json.load(response)
        # Policy configuration may contain user-managed values. Keep only executor/condition IDs.
        write(folder / ("client-policy-" + path.rsplit("/", 1)[-1] + ".json"), {
            "items": [{"name": item.get("name"), "enabled": item.get("enabled"),
                "conditions": [x.get("condition") for x in item.get("conditions", [])],
                "executors": [x.get("executor") for x in item.get("executors", [])]}
                for item in value.get("policies" if path.endswith("policies") else "profiles", [])]})

    scan = {"SAMLLoginResponseMapper": [], "SAMLNameIdMapper": [],
        "SamlAuthenticationPreprocessor": [], "preprocessorServiceFiles": [],
        "clientPolicySubjectWriters": [], "samlSubjectReferences": []}
    for jar in jars.rglob("*.jar"):
        with zipfile.ZipFile(jar) as archive:
            for entry in archive.namelist():
                if entry.startswith("META-INF/services/") and "SamlAuthenticationPreprocessor" in entry:
                    scan["preprocessorServiceFiles"].append(
                        "lib/" + str(jar.relative_to(jars)) + "!" + entry)
                if not entry.endswith(".class"): continue
                raw = archive.read(entry)
                location = "lib/" + str(jar.relative_to(jars)) + "!" + entry
                for term in TERMS:
                    if term in raw: scan[term.decode()].append(location)
                if b"SamlAuthenticationPreprocessor" in raw:
                    scan["SamlAuthenticationPreprocessor"].append(location)
                if "clientpolicy" in entry.lower() and any(term in raw for term in
                        (b"NameIDType", b"SubjectType", b"SAML2LoginResponseBuilder", b"SAMLNameIdMapper")):
                    scan["clientPolicySubjectWriters"].append(location)
                if "/protocol/saml/" in entry and b"SubjectType" in raw:
                    scan["samlSubjectReferences"].append(location)
    for value in scan.values(): value.sort()
    write(folder / "class-scan.json", scan)

    disassembly = folder / "disassembly"
    disassembly.mkdir(exist_ok=True)
    records = {}
    for label, (jar_rel, class_name) in CLASSES.items():
        jar = jars / jar_rel.removeprefix("lib/")
        raw = subprocess.check_output(["javap", "-classpath", str(jar), "-c", "-p", class_name], timeout=20)
        path = disassembly / (label + ".txt")
        path.write_bytes(raw)
        records[label] = {"jar": jar_rel, "class": class_name, "sha256": sha(raw)}
    write(folder / "disassembly-manifest.json", records)
    with zipfile.ZipFile(jars / ADMIN_UI.removeprefix("lib/")) as archive:
        matches = [(name, archive.read(name)) for name in archive.namelist()
            if name.endswith(".js") and b"attributes.saml_name_id_format" in archive.read(name)]
    if len(matches) != 1: raise RuntimeError("admin UI NameID setting ambiguous")
    ui_name, ui_raw = matches[0]
    (folder / "admin-ui-nameid.js").write_bytes(ui_raw)
    write(folder / "admin-ui-nameid.json", {"entry": ui_name, "sha256": sha(ui_raw),
        "optionsToken": 'options:["username","email","transient","persistent"]',
        "forceFormatToken": "attributes.saml_force_name_id_format"})
    print("Captured", len(copied), "runtime JARs and", len(mappers), "installed SAML mapper schemas")


if __name__ == "__main__":
    if len(sys.argv) != 2: raise SystemExit("usage: nameid_omission_runtime_audit.py EVIDENCE_DIR")
    main(sys.argv[1])
