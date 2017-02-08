#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""tagme-file utility.

tagme-file is a program to store arbitrary files with arbitrary tags attached
to them, and retrieve files by tags or their combinations.

This module should most likely not be imported.
"""

import hashlib
import os
import pickle
import shutil
import sys

HOME = os.path.expanduser("~/.tagme-file/")
FILES = HOME + "files.tmf"
TAGS = HOME + "tags.tmf"
STORAGE = HOME + "storage/"
HASH_BUFFER_SIZE = 2**20  # 1 MiB

if (os.path.exists(FILES) and os.path.exists(TAGS)):
    files = pickle.load(open(FILES, "rb"))
    tags = pickle.load(open(TAGS, "rb"))
else:
    files = {}
    tags = {}


def hash_file_sha3_512(file):
    """Perform sha3_512 hash on an arbitrary file and return the digest.

    File reading is buffered, so even super huge files can be hashed easily.

    file: path to file (usable with open()).

    return: hash of the file as int.
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
    """Put a file into storage and return it's sha3_512 hash digest as int.

    Path for a file in storage is generated as so:
    STORAGE/XX/YY/ZZZ...
    where XX are first byte of the hash in hex notation, YY are second byte,
    and ZZZ... (filename) are other 62 bytes.

    Int is used because this way digests need less memory to store. Smaller
    hash size can be used too, of course, but that is simply not as fun.

    file: path to file (usable with open()).

    return: hash of the file as int.
    """
    str_h = hash_file_sha3_512(file)

    prefix = "{}/{}/".format(str_h[:2], str_h[2:4])
    stored_file = STORAGE + prefix + str_h[4:]

    os.makedirs(STORAGE + prefix, mode=0o700, exist_ok=True)
    shutil.copy2(file, stored_file)

    return int(str_h, 16)


def add_tag(dg, t):
    """Perform all actions necessary to associate a tag with a digest.

    Actually, no checking is done, so it associates an arbitrary int with an
    arbitrary string.

    Adds a new digest to the 'files' dict, if it is not there yet, and assigns
    a list of tags (one tag in this case) to it. Otherwise, if the digest is
    already there, appends a new tag to the list associated with it if the tag
    is not there yet.

    Adds a new tag to the 'tags' dict, if it is not there yet, and assigns a
    list of digests (one digest in this case) to it. Otherwise, if the tag is
    already there, appends a new digest to the list associated with it if the
    digest is not there yet.

    dg: a digest, int, no checking is done, don't shoot yourself in the foot.
    t: a tag, string, same.
    """
    try:
        if t not in files[dg]:
            files[dg].append(t)
    except KeyError:
        files[dg] = [t]

    try:
        if dg not in tags[t]:
            tags[t].append(dg)
    except KeyError:
        tags[t] = [dg]


def cmd_add(filenames):
    """Perform 'add' command.

    Put files in storage and add their filename as first tag.

    filenames: list of filenames; should be valid paths.
    """
    for filename in filenames:
        sha3_hash = store(filename)
        add_tag(sha3_hash, os.path.basename(filename))


def cmd_describe_files():
    """Perform 'describe-files' command.

    Write out a list of all files (as hex digests) with their tags.
    """
    global files
    for file, tags in files.items():
        print("{:0128x}: {}".format(file, ", ".join(tags)))


def cmd_describe_tags():
    """Perform 'describe-tags' command.

    Write out a list of all tags with their files (as hex digests).
    """
    global tags
    for tag, files in tags.items():
        hex_digests = ["{:0128x}".format(file) for file in files]
        print("{:32}: {}".format(tag, ", ".join(hex_digests)))


def cmd_tag(str_digest, new_tags):
    """Perform 'tag' command.

    Add tags to given file (hex digest).
    """
    digest = int(str_digest, 16)
    for tag in new_tags:
        add_tag(digest, tag)


def main():
    """Run the tagme-file program; entry point."""
    # Create the home directory if it does not exist.
    # If it exists, do nothing, it's fine
    os.makedirs(HOME, mode=0o700, exist_ok=True)

    cmd = sys.argv[1]

    if cmd == "add":
        cmd_add(sys.argv[2:])
    elif cmd == "describe-files":
        cmd_describe_files()
    elif cmd == "describe-tags":
        cmd_describe_tags()
    elif cmd == "tag":
        cmd_tag(sys.argv[2], sys.argv[3:])

    pickle.dump(files, open(FILES, "wb"))
    pickle.dump(tags, open(TAGS, "wb"))


if __name__ == "__main__":
    main()
