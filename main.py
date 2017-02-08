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
    where XX are first two characters of the string digest, YY are 3rd and 4th,
    and ZZZ... (filename) are the rest.

    Int is used because this way digests need less memory to store. Smaller
    hash size can be used too, of course, but that is simply not as fun.

    file: path to file (usable with open()).

    return: hash of the file as int.
    """
    str_h = hash_file_sha3_512(file)

    prefix = "{}/{}/".format(str_h[:2], str_h[2:4])
    stored_file = STORAGE + prefix + str_h[4:]

    os.makedirs(STORAGE + prefix, exist_ok=True)
    shutil.copy2(file, stored_file)

    return int(str_h, 16)


def unstore(digest):
    """Remove a file corresponding to a digest from storage.

    digest: a digest of file to unstore
    """
    str_h = "{:0128x}".format(digest)

    prefix = "{}/{}/".format(str_h[:2], str_h[2:4])
    stored_file = STORAGE + prefix + str_h[4:]

    try:
        os.remove(stored_file)
        os.removedirs(STORAGE + prefix)
    except OSError as e:
        if not (e.errno == 2 or
                e.errno == 39):
            raise


def file_stored(digest):
    """Check if a file corresponding to given digest is in storage

    return: bool
    """
    str_h = "{:0128x}".format(digest)

    prefix = "{}/{}/".format(str_h[:2], str_h[2:4])
    stored_file = STORAGE + prefix + str_h[4:]

    return os.path.exists(stored_file)


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
    if not file_stored(dg):
        return

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


def del_tag(dg, t):
    """Perform all actions necessary to unassociate a tag from a digest.

    Actually, no checking is done, so it unassociates an arbitrary int from an
    arbitrary string.

    Removes the tag from the digest's tag list and removes the digest from the
    tag's digest list. If latter becomes empty as a result, removes the tag
    from 'tags' dict.

    Take note that a tag with no digests will be deleted, while a digest with
    no tags will be left alone. This is intended behaviour.

    dg: a digest, int, no checking is done, don't shoot yourself in the foot.
    t: a tag, string, same.
    """
    try:
        if t in files[dg]:
            files[dg].remove(t)
    except KeyError:
        pass

    try:
        if dg in tags[t]:
            tags[t].remove(dg)
    except KeyError:
        pass

    if not tags[t]:
        tags.pop(t)


def cmd_add(filenames):
    """Perform 'add' command.

    Put files in storage and add their filename as first tag.

    filenames: list of filenames; should be valid paths.
    """
    for filename in filenames:
        sha3_hash = store(filename)
        add_tag(sha3_hash, "name/" + os.path.basename(filename))


def cmd_describe_files():
    """Perform 'describe-files' command.

    Write out a list of all files (as string digests) with their tags.
    """
    global files
    for file, tags in files.items():
        print("{:0128x}: {}".format(file, ", ".join(tags)))


def cmd_describe_tags():
    """Perform 'describe-tags' command.

    Write out a list of all tags with their files (as string digests).
    """
    global tags
    for tag, files in tags.items():
        hex_digests = ["{:0128x}".format(file) for file in files]
        print("{:32}: {}".format(tag, ", ".join(hex_digests)))


def cmd_tag(str_digest, new_tags):
    """Perform 'tag' command.

    Add tags to given file (string digest).

    str_digest:
    """
    digest = int(str_digest, 16)
    for tag in new_tags:
        add_tag(digest, tag)


def cmd_remove(str_digests):
    """Perform 'remove' command.

    Remove all tags from given files and delete them from storage.

    filenames: list of digests of files to remove.
    """
    for str_digest in str_digests:
        digest = int(str_digest, 16)
        unstore(digest)
        for t in files[digest].copy():
            del_tag(digest, t)
        files.pop(digest)


def cmd_untag(str_digest, del_tags):
    """Perform 'untag' command.

    Remove given tags from given file (string digest).
    """
    digest = int(str_digest, 16)
    for tag in del_tags:
        del_tag(digest, tag)


def main():
    """Run the tagme-file program; entry point."""
    os.umask(0o077)

    # Create the home directory if it does not exist.
    # If it exists, do nothing, it's fine
    os.makedirs(HOME, exist_ok=True)

    cmd = sys.argv[1]

    if cmd == "add":
        cmd_add(sys.argv[2:])
    elif cmd == "describe-files":
        cmd_describe_files()
    elif cmd == "describe-tags":
        cmd_describe_tags()
    elif cmd == "tag":
        cmd_tag(sys.argv[2], sys.argv[3:])
    elif cmd == "remove":
        cmd_remove(sys.argv[2:])
    elif cmd == "untag":
        cmd_untag(sys.argv[2], sys.argv[3:])

    pickle.dump(files, open(FILES, "wb"))
    pickle.dump(tags, open(TAGS, "wb"))


if __name__ == "__main__":
    main()
