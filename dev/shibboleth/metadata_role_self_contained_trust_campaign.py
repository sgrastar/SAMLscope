#!/usr/bin/env python3
"""One actual metadata Run for role-key and self-contained signature/encryption trust."""
import argparse
from pathlib import Path
from metadata_role_key_campaign import collect
if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--reuse-prepared',type=Path);a=p.parse_args();collect(a.output,capture_trust=True,reuse_prepared=a.reuse_prepared)
