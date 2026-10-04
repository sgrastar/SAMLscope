#!/usr/bin/env python3
"""Install one verified SSP attribute-policy receipt and formally evaluate two proven cases."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request

from verify_ssp_attribute_policy_acceptance import verify_evidence, verify_receipt

BASE = "http://localhost:18080"
CASES = ["IIP-IDP03-a-idp-01", "IIP-IDP04-a-idp-01"]


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def api(path, body=None):
    request = urllib.request.Request(BASE + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("Evaluation directory must be empty")
    output.mkdir(parents=True, exist_ok=True)
    verified = verify_evidence(args.evidence)
    verify_receipt(verified, args.receipt)
    run = verified["run"]
    target = "/data/attribute-policy-preparations/" + run + ".json"
    exists = subprocess.run(["docker", "exec", "samlscope-reference-suite", "test", "-e", target])
    if exists.returncode == 0:
        raise ValueError("Refusing to overwrite a preparation receipt")
    subprocess.run(["docker", "cp", str(args.receipt.resolve()),
                    "samlscope-reference-suite:" + target], check=True, timeout=120)
    readback = subprocess.run(["docker", "exec", "samlscope-reference-suite", "cat", target],
                              check=True, stdout=subprocess.PIPE, timeout=120).stdout
    expected = args.receipt.read_bytes()
    if readback != expected:
        raise RuntimeError("Receipt read-back mismatch")
    save(output / "receipt-install.json", {"run": run, "path": target,
        "sha256": hashlib.sha256(expected).hexdigest(), "readBack": True, "overwritten": False})
    save(output / "evaluate-before-confirmation.json",
         api("/api/runs/" + run + "/protocol-evidence/evaluate", {}))
    for case in CASES:
        save(output / (case + "-configure.json"),
             api("/api/runs/" + run + "/cases/" + case + "/configure", {"value": "confirmed"}))
    save(output / "evaluate-after-confirmation.json",
         api("/api/runs/" + run + "/protocol-evidence/evaluate", {}))
    for endpoint in ["result.json", "transcript", "protocol-evidence"]:
        save(output / (endpoint if "." in endpoint else endpoint + ".json"),
             api("/api/runs/" + run + "/" + endpoint))
    result = json.loads((output / "result.json").read_text())
    cases = {case["id"]: case for requirement in result["requirements"] for case in requirement["cases"]}
    for case in CASES:
        if (cases[case]["outcome"], cases[case]["verdict"], cases[case]["reason_code"]) != (
                "SATISFIED", "PASS", "configuration.attribute-policy.comparison-observed"):
            raise RuntimeError("Proven case did not evaluate to SATISFIED: " + case)
    unresolved = cases["IIP-IDP04-b-idp-01"]
    if unresolved["outcome"] != "NOT_VERIFIED" or unresolved["verdict"] != "NOT_VERIFIED":
        raise RuntimeError("Unproven indexed case changed unexpectedly")
    save(output / "operations.json", {"receiptPlacements": 1, "receiptReadBacks": 1,
        "configurationConfirmations": len(CASES), "protocolEvaluations": 2,
        "productConfigurationWrites": 0, "productRestarts": 0, "humanOperations": 0})
    print("Formally evaluated", ", ".join(CASES), "for", run)


if __name__ == "__main__":
    main()
