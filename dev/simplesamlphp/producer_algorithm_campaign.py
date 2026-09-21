#!/usr/bin/env python3
"""Record native Assertion encryption after an unencrypted control, with exact restoration.

Algorithm identifiers come from the signed output, never from requested configuration.
The campaign enables the installed product's implementation; it does not replace its
key transport or encryption generator. Formal evidence qualification is separate.
"""
from signature_modes_campaign import main

if __name__ == '__main__':
    main(default_matrix='encryption')
