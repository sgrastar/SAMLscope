#!/usr/bin/env python3
"""Collect four independently Run-bound EXT01.b observations for one reference IdP.

Each product driver owns native configuration, read-back, restoration, and transcript export. This
wrapper only runs the approved profile set and captures the deployed Suite identity after each
restored campaign. A failed profile stops the batch; completed profile folders remain immutable.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys


REPO = Path(__file__).resolve().parents[2]
PROFILES = ("browser_sso_idp", "ecp_idp", "metadata_idp", "single_logout_idp")
DRIVERS = {
    "keycloak": REPO / "dev/keycloak/browser_chain_campaign.py",
    "shibboleth": REPO / "dev/shibboleth/browser_chain_campaign.py",
    "simplesamlphp": REPO / "dev/simplesamlphp/browser_chain_campaign.py",
}
CAPTURE = REPO / "dev/reference-acceptance/capture_terminal_http_runtime.py"
CASE = "IIP-EXT01-b-idp-01"


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", choices=tuple(DRIVERS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--playwright-modules", type=Path,
                        help="Required by the Keycloak native console driver")
    args = parser.parse_args()
    root = args.output.resolve()
    if root.exists() and any(root.iterdir()):
        raise ValueError("Evidence directory must be empty")
    root.mkdir(parents=True, exist_ok=True)
    if args.product == "keycloak" and args.playwright_modules is None:
        parser.error("--playwright-modules is required for Keycloak")

    completed = []
    save(root / "batch.json", {"schema": "samlscope-ext01b-batch-v1",
                                "product": args.product, "profiles": list(PROFILES),
                                "case": CASE, "completed": completed,
                                "verdict_adopted": False})
    for profile in PROFILES:
        folder = root / profile
        command = [sys.executable, str(DRIVERS[args.product]),
                   "--output", str(folder), "--profile", profile,
                   "--stop-after-case", CASE]
        if args.product == "keycloak":
            command += ["--playwright-modules", str(args.playwright_modules.resolve())]
        if args.product == "simplesamlphp" and profile != "browser_sso_idp":
            command.append("--no-idp-initiated-sso")
        subprocess.run(command, cwd=REPO, check=True)
        subprocess.run([sys.executable, str(CAPTURE), str(folder), "suite"],
                       cwd=REPO, check=True)
        completed.append({"profile": profile,
                          "run": json.loads((folder / "created.json").read_text())["run"]["id"]})
        save(root / "batch.json", {"schema": "samlscope-ext01b-batch-v1",
                                    "product": args.product, "profiles": list(PROFILES),
                                    "case": CASE, "completed": completed,
                                    "verdict_adopted": False})


if __name__ == "__main__":
    main()
