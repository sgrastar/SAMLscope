#!/usr/bin/env python3
"""Install native originals, re-evaluate the immutable Run, and bind the evaluation runtime."""
import argparse
from datetime import datetime, timezone
import json
import hashlib
import subprocess
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from install_metadata_refresh_receipt import install
sys.path.insert(0, str(REPO / "dev/reference-acceptance"))
from capture_terminal_http_runtime import capture_suite, api


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()
    folder = args.folder.resolve()
    run = install(folder)
    transcript = json.loads((folder / "transcript.json").read_text())
    if api("/api/runs/" + run + "/transcript") != transcript:
        raise RuntimeError("Live transcript differs from originals")
    started = datetime.now(timezone.utc).isoformat()
    capture_suite(folder)
    subprocess.run(["docker", "cp", "samlscope-reference-suite:/opt/samlscope/lib/store-0.1.0.jar",
                    str(folder / "suite-store-0.1.0.jar")], check=True, timeout=30,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (folder / "store-runtime.json").write_text(json.dumps(dict(
        path="/opt/samlscope/lib/store-0.1.0.jar", file="suite-store-0.1.0.jar",
        sha256=hashlib.sha256((folder / "suite-store-0.1.0.jar").read_bytes()).hexdigest()), indent=2) + "\n")
    result = json.loads((folder / "evaluation-terminal-http-v1/result.json").read_text())
    case = next(case for requirement in result["requirements"] for case in requirement["cases"]
                if case["id"] == "IIP-MD02-a-idp-01")
    (folder / "formal-evaluation.json").write_text(json.dumps(dict(
        runId=run, startedAt=started, finishedAt=datetime.now(timezone.utc).isoformat(),
        transcriptUnchanged=True, case=case), indent=2) + "\n")
    if (case["outcome"], case["verdict"], case["reason_code"], case["attested"]) != (
            "SATISFIED", "PASS", "metadata.native-refresh-observed", False):
        raise RuntimeError("Formal refresh remains unproven: " + repr(case))
    print(run, "MD02.a formally satisfied; transcript unchanged")


if __name__ == "__main__":
    main()
