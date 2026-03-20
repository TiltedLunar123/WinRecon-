"""Allow running WinRecon as a module: python -m winrecon."""

import sys

from winrecon.cli import main

if __name__ == "__main__":
    sys.exit(main())
