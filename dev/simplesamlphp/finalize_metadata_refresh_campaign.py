#!/usr/bin/env python3
"""Install, formally re-evaluate, and capture Suite identity for one MD02.a campaign."""
import argparse
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dev/keycloak"))
from import_metadata_batch import api, save
sys.path.insert(0, str(Path(__file__).resolve().parent))
from install_metadata_refresh_receipt import install
sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
from capture_terminal_http_runtime import capture_suite

CASE = "IIP-MD02-a-idp-01"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()
    folder = args.folder.resolve()
    installed = folder / "metadata-refresh-receipt-install.json"
    run = json.loads(installed.read_text())["runId"] if installed.exists() else install(folder)
    exported = json.loads((folder / "transcript.json").read_text())
    if api("/api/runs/" + run + "/transcript") != exported:
        raise RuntimeError("Live transcript differs before formal adoption")
    # Receipt-backed cases are re-evaluated from the immutable transcript and originals when the
    # result is read.  ConfigurationService deliberately rejects operator confirmation here.
    save(folder / "configure.json", dict(mode="transcript-driven", operatorConfirmation=False,
                                          reevaluation="result-read", caseId=CASE))
    after = api("/api/runs/" + run + "/transcript")
    if after != exported:
        raise RuntimeError("Configuration confirmation changed the transcript")
    save(folder / "adopted-transcript.json", after)
    result = api("/api/runs/" + run + "/result.json")
    save(folder / "result-after.json", result)
    save(folder / "result.json", result)
    capture_suite(folder)
    print(run, "formally re-evaluated")


if __name__ == "__main__":
    main()
