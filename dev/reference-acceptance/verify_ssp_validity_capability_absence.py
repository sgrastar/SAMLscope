"""Adopt SSP MD04.a/c only from native use plus replayable capability evidence."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import tarfile
import tempfile
import xml.etree.ElementTree as ET


FOLDER = "ssp-validity-capability-v158"
CASES = ("IIP-MD04-a-idp-01", "IIP-MD04-c-idp-01")
VARIANTS = ("control", "no-valid-until", "valid-until-near", "valid-until-far")
TARGET = "http://localhost:18380/idp"
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
MD = "urn:oasis:names:tc:SAML:2.0:metadata"
PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"


def require(value: object, message: str) -> None:
    if not value:
        raise AssertionError(message)


def read(folder: Path, name: str):
    return json.loads((folder / name).read_text())


def case_map(result: dict) -> dict:
    return {case["id"]: case for requirement in result["requirements"] for case in requirement["cases"]}


def iso_epoch(value: str) -> int:
    # Suite fixtures retain nanoseconds while Python datetime accepts microseconds.
    match = re.fullmatch(r"(.+?)(?:\.(\d+))?Z", value)
    require(match is not None, "invalid validUntil")
    fraction = ((match.group(2) or "") + "000000")[:6]
    parsed = datetime.fromisoformat(match.group(1) + ("." + fraction if fraction else "") + "+00:00")
    return int(parsed.timestamp())


def verify_source_archive(folder: Path, runtime: dict) -> dict[str, bytes]:
    archive = (folder / "runtime-validity-source.tar.gz").read_bytes()
    require(SHA(archive) == runtime["archive_sha256"], "runtime source archive hash mismatch")
    members, occurrences, sources = [], [], {}
    search = re.compile(runtime["search_pattern"], re.I)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
        for member in sorted(source.getmembers(), key=lambda item: item.name):
            if not member.isfile():
                continue
            raw = source.extractfile(member).read()
            sources[member.name] = raw
            members.append({"path": member.name, "size": len(raw), "sha256": SHA(raw)})
            if member.name.endswith((".php", ".md", ".json", ".lock")):
                for number, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
                    if search.search(line):
                        occurrences.append({"path": member.name, "line": number, "text": line})
    require(members == runtime["members"], "runtime source member inventory mismatch")
    require(occurrences == runtime["occurrences"], "runtime source search replay mismatch")
    require(len(members) > 2000, "runtime source inventory is unexpectedly narrow")
    required = {
        "src/SimpleSAML/Metadata/SAMLParser.php",
        "modules/metarefresh/src/MetaRefresh.php",
        "modules/metarefresh/src/MetaLoader.php",
        "modules/metarefresh/config-templates/module_metarefresh.php",
        "vendor/simplesamlphp/saml2/src/XML/md/AbstractMetadataDocument.php",
        "vendor/simplesamlphp/saml2-legacy/src/SAML2/XML/md/EntityDescriptor.php",
        "composer.lock",
    }
    require(required <= sources.keys(), "validity call path is missing from retained source")

    parser = sources["src/SimpleSAML/Metadata/SAMLParser.php"]
    require(b"$expire = $element->getValidUntil();" in parser, "validUntil read changed")
    require(b"$expire === null || $maxExpireTime < $expire" in parser,
            "missing-validUntil/future clamp changed")
    require(b"$expire = $maxExpireTime;" in parser and b"return $expire;" in parser,
            "expiry clamp return changed")
    require(b"return self::processDescriptorsElement(new EntityDescriptor($element));" in parser,
            "EntityDescriptor parser path changed")

    refresh = sources["modules/metarefresh/src/MetaRefresh.php"]
    require(b"getOptionalInteger('expireAfter', null)" in refresh
            and b"$expire = time() + $expireAfter;" in refresh
            and b"new MetaLoader($expire" in refresh,
            "expireAfter configuration path changed")
    loader = sources["modules/metarefresh/src/MetaLoader.php"]
    require(b"return Metadata\\SAMLParser::parseDescriptorsElement($doc->documentElement);" in loader,
            "metarefresh parser path changed")
    require(b"if ($this->expire < $metadata['expire'])" in loader
            and b"$metadata['expire'] = $this->expire;" in loader,
            "metarefresh expiry clamp changed")
    require(b"else {\n                $metadata['expire'] = $this->expire;" in loader,
            "missing-validUntil expiry fallback changed")

    executable = [row for row in occurrences if row["path"].endswith(".php")]
    expire_after_paths = {row["path"] for row in executable if "expireAfter" in row["text"]}
    require(expire_after_paths == {
        "modules/metarefresh/src/MetaRefresh.php",
        "modules/metarefresh/config-templates/module_metarefresh.php",
    }, "unreviewed expireAfter implementation exists")
    forbidden = [row for row in executable
                 if re.search(r"maxValidity|requiredValid|validityInterval", row["text"], re.I)]
    require(not forbidden, "unreviewed validity rejection setting exists")
    return sources


def verify_replay(folder: Path, fixtures: dict[str, ET.Element]) -> None:
    replay = read(folder, "expire-after-replay.json")
    require(replay["schema"] == "samlscope-ssp-expire-after-replay-v1", "bad replay schema")
    require(replay["expire_after_seconds"] == 20 * 24 * 60 * 60, "unexpected replay threshold")
    harness = (folder / "expire-after-replay.php").read_bytes()
    require(SHA(harness) == replay["harness_sha256"], "replay harness hash mismatch")
    require(replay["temporary_files_removed"] is True, "temporary replay files remain")
    require((replay["product_configuration_writes"], replay["product_restarts"], replay["human_operations"])
            == (0, 0, 0), "replay mutated the product or used a person")
    records = replay["records"]
    require([row["variant"] for row in records] == list(VARIANTS), "replay variant order changed")
    for row in records:
        variant = row["variant"]
        raw = (folder / variant / "fixture.xml").read_bytes()
        require(row["fixture_sha256"] == SHA(raw), "replay fixture hash mismatch")
        categories = row["metadata"]
        require(set(categories) == {"saml20-sp-remote"}
                and len(categories["saml20-sp-remote"]) == 1, "fixture was not natively parsed as one SP")
        metadata = categories["saml20-sp-remote"][0]["metadata"]
        require(metadata["entityid"].startswith("http://localhost:18080/p/plan_"), "wrong parsed entity")
        require(metadata.get("AssertionConsumerService"), "parsed metadata is unusable")
        expire = metadata.get("expire")
        require(isinstance(expire, int), "native parser omitted effective expiry")
        if variant in {"no-valid-until", "valid-until-far"}:
            require(expire == row["limit"], "expireAfter did not clamp/fill instead of rejecting")
        else:
            require(expire == iso_epoch(fixtures[variant].attrib["validUntil"]),
                    "native parser changed an in-bound validity value")
            require(expire < row["limit"], "control/near fixture is not below T")


def verify_protocol(folder: Path, run: str, plan: str) -> None:
    transcript_rows = read(folder, "transcript.json")
    require(transcript_rows == read(folder, "transcript-after.json"), "configuration conclusion changed transcript")
    transcript = {row["id"]: row for row in transcript_rows}
    manifest_rows = read(folder, "decoded-manifest.json")
    manifest = {row["id"]: row for row in manifest_rows}
    require(len(manifest) == len(manifest_rows), "duplicate decoded original")
    roots = {}
    for reference, row in manifest.items():
        path = (folder / row["file"]).resolve()
        require(path.parent == (folder / "decoded").resolve(), "decoded original escaped directory")
        raw = path.read_bytes()
        require(SHA(raw) == row["sha256"], "decoded original hash mismatch")
        entry = transcript[reference]
        require(entry["runId"] == run and entry["decodedSamlBytes"] == len(raw), "decoded original binding mismatch")
        roots[reference] = ET.fromstring(raw)

    for variant in VARIANTS:
        operation = read(folder / variant, "operation.json")
        flow = read(folder / variant, "flow.json")
        fixture = (folder / variant / "fixture.xml").read_bytes()
        require(operation == {
            "variant": variant, "status": "success", "source": "simplesamlphp-native-mdq",
            "fixture_sha256": SHA(fixture),
            "native_fetch_count_before": VARIANTS.index(variant),
            "native_fetch_count_after": VARIANTS.index(variant) + 1,
        }, "native product fetch operation mismatch")
        require(flow["run"] == run and flow["variant"] == variant and flow["correlated_success"] is True,
                "native product flow did not produce correlated Success")
        require(flow["after_index"] == flow["before_index"] + 1, "campaign did not advance exactly once")
        request_ref, response_ref = flow["positive_exchange"]["transcript_ids"]
        request, response = roots[request_ref], roots[response_ref]
        require(request.tag == f"{{{PROTOCOL}}}AuthnRequest" and response.tag == f"{{{PROTOCOL}}}Response",
                "flow originals are not AuthnRequest/Response")
        require(response.attrib.get("InResponseTo") == request.attrib.get("ID"), "flow correlation mismatch")
        status = response.find(f"{{{PROTOCOL}}}Status/{{{PROTOCOL}}}StatusCode")
        require(status is not None and status.attrib.get("Value", "").endswith(":Success"),
                "native use did not return SAML Success")
        prepared = [entry for entry in transcript_rows
                    if entry.get("samlSummary", {}).get("type") == "MetadataPrepared"
                    and entry.get("samlSummary", {}).get("variant") == variant]
        require(len(prepared) == 2, "expected gate and native MDQ metadata originals")
        delivered = (folder / variant / "proxy-response.xml").read_bytes()
        delivered_hashes = {
            SHA((folder / manifest[row["id"]]["file"]).read_bytes()) for row in prepared
        }
        # Time-relative fixtures are rendered once for the gate and once for the
        # product fetch.  Their signatures therefore differ.  Retain and bind
        # both originals rather than pretending the two responses are byte equal.
        require(all(roots[row["id"]].tag in {
                    f"{{{MD}}}EntityDescriptor", f"{{{MD}}}EntitiesDescriptor"
                } for row in prepared)
                and delivered_hashes == {SHA(fixture), SHA(delivered)},
                "gate/native metadata originals do not match the retained responses")
        proxy_lines = (folder / variant / "proxy-requests.jsonl").read_text().splitlines()
        require(len(proxy_lines) == VARIANTS.index(variant) + 1, "native relay request history mismatch")
        last = json.loads(proxy_lines[-1])
        require(last == {
            "entityId": ET.fromstring(delivered).attrib["entityID"],
            "sourceUrl": f"http://samlscope-reference-suite:8080/p/{plan}/metadata/live?run={run}",
            "responseSha256": SHA(delivered),
            "httpStatus": 200,
            "observedAt": last.get("observedAt"),
        } and last["observedAt"].endswith("Z"), "native relay request identity mismatch")
    require(plan.startswith("plan_"), "invalid plan binding")


def _verify(folder: Path):
    result = read(folder, "result.json")
    require(result == read(folder, "result-after.json"),
            "configuration conclusion changed the formal result")
    run = result["run"]["id"]
    created = read(folder, "created.json")
    require(created["run"]["id"] == run, "Run identity mismatch")
    plan_data = read(folder, "plan.json")["plan"]["plan"]
    require(plan_data["id"] == created["run"]["planId"] and plan_data["profile"] == "metadata_idp",
            "wrong Plan")
    require(plan_data["target"]["entityId"] == TARGET, "wrong target entity")

    original = (folder / "original-config.php").read_bytes()
    final = (folder / "final-config.php").read_bytes()
    restoration = read(folder, "restoration.json")
    require(original == final and restoration == {
        "restored": True, "original_sha256": SHA(original), "final_sha256": SHA(final),
    }, "product configuration restoration mismatch")
    operations = read(folder, "operation-counts.json")
    require(operations["product_configuration_writes"] == 2
            and operations["restoration_writes"] == 1
            and operations["product_restarts"] == 0
            and operations["human_operations"] == 0
            and operations["restored"] is True, "operation counts changed")

    start, end = read(folder, "target-runtime-start.json"), read(folder, "target-runtime-end.json")
    require(start["binding"] == end["binding"], "product runtime changed during campaign")
    require(start["version_source"]["value"] == end["version_source"]["value"] == "2.5.0",
            "unexpected product version")
    require(start["version_source"]["sha256"] == end["version_source"]["sha256"],
            "version source changed")
    runtime = read(folder, "runtime-validity-source.json")
    require((runtime["container_id"], runtime["image_id"], runtime["container_started_at"]) == (
        start["binding"]["container_id"], start["binding"]["image_id"],
        start["binding"]["container_started_at"]), "source archive is from another product runtime")
    require((runtime["product_configuration_writes"], runtime["product_restarts"], runtime["human_operations"])
            == (0, 0, 0), "source capture mutated the product or used a person")
    verify_source_archive(folder, runtime)

    fixtures = {variant: ET.fromstring((folder / variant / "fixture.xml").read_bytes())
                for variant in VARIANTS}
    require(fixtures["no-valid-until"].attrib.get("validUntil") is None,
            "missing-validUntil control contains the attribute")
    near = iso_epoch(fixtures["valid-until-near"].attrib["validUntil"])
    far = iso_epoch(fixtures["valid-until-far"].attrib["validUntil"])
    require(0 < far - near < 3 * 24 * 60 * 60, "boundary fixture pair changed")
    verify_replay(folder, fixtures)
    verify_protocol(folder, run, plan_data["id"])

    target = (folder / "target-metadata.xml").read_bytes()
    require(result["target"]["metadata_digest"] == "sha256:" + SHA(target), "target metadata mismatch")
    target_root = ET.fromstring(target)
    require(any(element.attrib.get("entityID") == TARGET for element in target_root.iter()),
            "target metadata does not contain the target")
    cases = case_map(result)
    for case in CASES:
        row = cases[case]
        require((row["outcome"], row["verdict"], row["reason_code"], row["attested"])
                == ("VIOLATED", "FAIL", "metadata.fixture-probe.violated", False),
                "formal native validity failure changed")
        require(row["evidence"], "formal failure lacks protocol evidence")
    require(result["run"]["conformance"] == "NON_CONFORMANT", "MUST failures did not affect conformance")
    require(set(cases[CASES[0]]["diagnostics"]["used_variants"]) == {"control", "no-valid-until"},
            "MD04.a variants changed")
    require(set(cases[CASES[1]]["diagnostics"]["used_variants"])
            == {"control", "valid-until-near", "valid-until-far"}, "MD04.c variants changed")
    return folder / "result.json", {case: cases[case] for case in CASES}


def verify(root):
    folder = Path(root) / FOLDER
    selected = _verify(folder)
    mutations = {
        "restoration": ("restoration.json", lambda value: value.__setitem__("restored", False)),
        "native-use": ("no-valid-until/flow.json", lambda value: value.__setitem__("correlated_success", False)),
        "expiry-clamp": ("expire-after-replay.json",
                         lambda value: value["records"][3].__setitem__("limit", value["records"][3]["limit"] + 1)),
        "source-manifest": ("runtime-validity-source.json",
                            lambda value: value.__setitem__("archive_sha256", "0" * 64)),
        "formal-result": ("result.json", lambda value: next(
            case for requirement in value["requirements"] for case in requirement["cases"]
            if case["id"] == CASES[0]).__setitem__("verdict", "PASS")),
    }
    outcomes = {}
    for name, (relative, mutate) in mutations.items():
        with tempfile.TemporaryDirectory(prefix="samlscope-validity-tamper-") as temporary:
            clone = Path(temporary) / FOLDER
            shutil.copytree(folder, clone)
            path = clone / relative
            value = json.loads(path.read_text())
            mutate(value)
            path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
            try:
                _verify(clone)
            except (AssertionError, KeyError, ValueError, ET.ParseError):
                outcomes[name] = "NOT_VERIFIED"
            else:
                raise AssertionError("tamper was accepted: " + name)
    require(set(outcomes.values()) == {"NOT_VERIFIED"} and len(outcomes) == len(mutations),
            "tamper controls incomplete")
    return selected


if __name__ == "__main__":
    import sys
    path, cases = verify(sys.argv[1])
    print(path)
    for case, row in cases.items():
        print(case, row["verdict"], "native validity capability absent")
