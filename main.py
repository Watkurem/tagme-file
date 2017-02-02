#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""tagme-file utility.

tagme-file is a program to store arbitrary files with arbitrary tags attached
to them, and retrieve files by tags or their combinations.

This module should most likely not be imported.
"""

import os


def main():
    """Runs the tagme-file program; entry point."""
    os.makedirs(os.path.expanduser("~/.tagme-file"), mode=0o700, exist_ok=True)


if __name__ == "__main__":
    main()
