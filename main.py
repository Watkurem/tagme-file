#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""tagme-file utility.

tagme-file is a program to store arbitrary files with arbitrary tags attached
to them, and retrieve files by tags or their combinations.

This module should most likely not be imported.
"""

import hashlib
import os
import shutil
import sys

HOME = os.path.expanduser("~/.tagme-file/")
STORAGE = HOME + "storage/"
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

    return hasher.hexdigest()


def store(file):
    """Put a file into storage and return it's sha3_512 hash digest as int

    Path for a file in storage is generated as so:
    STORAGE/XX/YY/ZZZ...
    where XX are first byte of the hash in hex notation, YY are second byte,
    and ZZZ... (filename) are other 62 bytes.

    Int is used because this way digests need less memory to store. Smaller
    hash size can be used too, of course, but that is simply not as fun.

    file: path to file (usable with open())

    return: hash of the file as int
    """
    str_h = hash_file_sha3_512(file)

    prefix = "{}/{}/".format(str_h[:2], str_h[2:4])
    store_file = STORAGE + prefix + str_h[4:]

    os.makedirs(STORAGE + prefix, mode=0o700, exist_ok=True)
    shutil.copy2(file, store_file)

    return int(str_h, 16)


def main():
    """Runs the tagme-file program; entry point."""
    # Create the home directory if it does not exist.
    # If it exists, do nothing, it's fine
    os.makedirs(HOME, mode=0o700, exist_ok=True)


if __name__ == "__main__":
    main()
