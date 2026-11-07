# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Allow ``python -m faithful_shaar``."""

import sys

from faithful_shaar.cli import main

if __name__ == "__main__":
    sys.exit(main())
