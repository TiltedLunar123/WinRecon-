#!/usr/bin/env python3
"""Backward-compatible entry point. Use ``python -m winrecon`` instead."""

import sys

from winrecon.cli import main

if __name__ == "__main__":
    sys.exit(main())
