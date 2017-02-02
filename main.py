#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""tagme-file utility.

tagme-file is a program to store arbitrary files with arbitrary tags attached
to them, and retrieve files by tags or their combinations.

This module should most likely not be imported.
"""

import hashlib
import os

HOME = os.path.expanduser("~/.tagme-file")
STORAGE = HOME + "/storage"
HASH_BUFFER_SIZE = 2**20  # 1 MiB


def hash_file_sha3_512(file):
    """Perform sha3_512 hash on an arbitrary file and return the digest

    File reading is buffered, so even super huge files can be hashed easily.

    file: path to file (usable with open())

    return: hash of the file as int
    """
    hasher = hashlib.sha3_512()

    with open(file, mode='rb', buffering=HASH_BUFFER_SIZE) as f:
        while f.readable():
            data = f.read(HASH_BUFFER_SIZE)
            if not data:
                break
            hasher.update(data)

    return int(hasher.hexdigest(), 16)


def main():
    """Runs the tagme-file program; entry point."""
    # Create the home directory if it does not exist.
    # If it exists, do nothing, it's fine
    os.makedirs(HOME, mode=0o700, exist_ok=True)


if __name__ == "__main__":
    main()
