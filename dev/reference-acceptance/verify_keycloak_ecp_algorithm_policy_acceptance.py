#!/usr/bin/env python3
"""Verify native algorithm prevention using this Run's own seven outbox ECP controls."""
import argparse
import json
from pathlib import Path
from verify_keycloak_algorithm_policy_acceptance import verify as common_verify

FOLDER = "keycloak-alg08-native-policy-ecp-v164"


def verify(folder, formal=True, live=True):
    baseline = json.loads((folder / "browser-baseline.json").read_bytes())
    if baseline != dict(status="recorded", protocolOperations=1):
        raise ValueError("ECP Run's required browser baseline did not finish")
    return common_verify(folder, formal=formal, live=live, profile="ecp_idp",
        helper_name="VerifyKeycloakEcpAlgorithmPreventionEvidence")


def verify_adoption(root, live=True):
    return verify(Path(root) / FOLDER, live=live)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--diagnostic", action="store_true")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    result = verify(args.folder.resolve(), formal=not args.diagnostic, live=not args.offline)
    if isinstance(result, tuple):
        print(result[0], "native ECP prevention adopted", len(result[1]))
    else:
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
