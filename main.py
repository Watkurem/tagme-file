#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""tagme-file utility.

tagme-file is a program to store arbitrary files with arbitrary tags attached
to them, and retrieve files by tags or their combinations.

This module should most likely not be imported.
"""

import base64
import hashlib
import os
import pickle
import re
import shutil
import sys

HOME = os.path.expanduser("~/.tagme-file/")
FILES = HOME + "files.tmf"
TAGS = HOME + "tags.tmf"
LAST = HOME + "last.tmf"
STORAGE = HOME + "storage/"
HASH_BUFFER_SIZE = 2**20  # 1 MiB

# 'files' and 'tags' are dictionaries that store, respectively:
# - The (int) file digests as keys and lists of those files' (string) tags as
#   values;
# - The (string) tags as keys and lists of (int) file digests tagged with those
#   tags as values;
# tagme-file will attempt to load 'files' and 'tags' from the paths stored in
# FILES and TAGS respectively. Then, at exit, said files will be overwritten or
# created, if they did not exist.
if (os.path.exists(FILES) and os.path.exists(TAGS)):
    files = pickle.load(open(FILES, "rb"))
    tags = pickle.load(open(TAGS, "rb"))
else:
    files = {}
    tags = {}

# 'last' is a tuple that stores the last accessed (int) file digests. It is
# useful for situations like the following example and greatly simplifies
# user's interaction with the program.
# Example:
# $ tagme-file add f1 f2 f3
# $ tagme-file tag last t1 t2 t3
# As a result, files f1, f2, f3 will be tagged with tags t1, t2, t3.
if os.path.exists(LAST):
    last = pickle.load(open(LAST, "rb"))
else:
    last = ()


def digest_to_str(digest):
    """Convert a digest from int to base64 string representation.

    digest: 512-bit int digest that will be stringified

    return: 86-character string containing little-endian base64 representation
            of digest with padding '==' stripped
    """
    ascii_b64 = base64.urlsafe_b64encode(digest.to_bytes(64, "little"))[:-2]
    return str(ascii_b64, "ascii")


def str_to_digest(str_digest):
    """Convert a little-endian base64 string representation of digest to int.

    str_digest: 86-character string containing little-endian base64
                representation of digest with padding '==' stripped

    return: 512-bit int digest
    """
    ascii_b64 = bytes(str_digest, 'ascii') + b'=='
    return int.from_bytes(base64.urlsafe_b64decode(ascii_b64), "little")


def split_name_ext(filename):
    """Split a filename into name-extension pair.

    Take note: split_name_ext("file.tar.xz") => ("file", "tar.xz"),
    not ("file.tar", "xz")

    filename: a string filename. May be full filename (with path)

    return: (name, ext)
    name: name part of filename (without path)
    ext: extension part of filename
    """
    basename = os.path.basename(filename)

    # The case of files like '.hidden' where the period is first symbol
    if basename[0] == '.':
        name = basename
        ext = None
    # The case of other files
    else:
        split_name = basename.split(".", 1)
        try:
            name = split_name[0]
            ext = split_name[1]
        except IndexError:
            name = basename
            ext = None

    return name, ext


def get_ext(digest):
    """Return the extension associated with given digest.

    Currently extension is stored as special tag 'ext/<extension>'. Last
    occurence of said tag in the file's tag list is considered most recent and
    current extension

    digest: digest to look up the extension for

    return: string extension (without period prefix) or None if no extension is
            associated with digest
    """
    try:
        return next((tag[4:] for tag in reversed(files[digest])
                     if tag.startswith('ext/')))
    except StopIteration:
        return None



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

    return int(hasher.hexdigest(), 16)


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
    h = hash_file_sha3_512(file)
    str_h = digest_to_str(h)

    prefix = "{}/{}/".format(str_h[:2], str_h[2:4])
    stored_file = STORAGE + prefix + str_h[4:]

    os.makedirs(STORAGE + prefix, exist_ok=True)
    shutil.copy2(file, stored_file)

    files[h] = []

    return h


def unstore(digest):
    """Remove a file corresponding to a digest from storage.

    digest: a digest of file to unstore
    """
    str_h = digest_to_str(digest)

    prefix = "{}/{}/".format(str_h[:2], str_h[2:4])
    stored_file = STORAGE + prefix + str_h[4:]

    try:
        os.remove(stored_file)
        os.removedirs(STORAGE + prefix)
    except OSError as e:
        if not (e.errno == 2 or
                e.errno == 39):
            raise


def copy_out(digest):
    """Copy a file from storage to current directory.

    digest: a digest of file to copy
    """
    if not file_stored(digest):
        return

    str_h = digest_to_str(digest)

    prefix = "{}/{}/".format(str_h[:2], str_h[2:4])
    stored_file = STORAGE + prefix + str_h[4:]

    ext = get_ext(digest)
    if ext is not None:
        shutil.copy2(stored_file,
                     "{}/{}.{}".format(os.getcwd(), str_h, ext))
    else:
        shutil.copy2(stored_file,
                     "{}/{}".format(os.getcwd(), str_h))


def file_stored(digest):
    """Check if a file corresponding to given digest is in storage

    return: bool
    """
    str_h = digest_to_str(digest)

    prefix = "{}/{}/".format(str_h[:2], str_h[2:4])
    stored_file = STORAGE + prefix + str_h[4:]

    # Kinda assert
    assert(os.path.exists(stored_file) == (digest in files))

    return (os.path.exists(stored_file) and digest in files)


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

    files[dg].append(t)

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


def to_rpn(query):
    """Process a string infix query and return it's RPN representation.

    Three operators are recognized:
    - Nothing (or whitespace) between tokens means 'AND';
    - '|' means 'OR';
    - '!' means NOT (unary).
    All other characters are considered parts of tokens (tags).

    In RPN representation '+' is used for AND.

    The precedence is as follows: | < + < !.

    query: an infix query string, e.g. 't1 (t2|t3) | t4'

    return: a list with RPN representation of the query, e.g.:
            ['t1', 't2', 't3', '|', '+', 't4', '|']
    """
    output = []
    stack = [None]

    _input = re.split(r'\s+|(\||!|\(|\))', query)
    input = [x for x in _input if (x != '' and x is not None)]

    for x, next in zip(input, input[1:] + [None]):
        if x == '!':
            stack.append(x)
        elif x == '|':
            while stack[-1] in ('+', '|'):
                output.append(stack.pop())
            stack.append(x)
        elif x == "(":
            stack.append(x)
        elif x == ")":
            while stack[-1] != '(':
                output.append(stack.pop())
            stack.pop()
            if next not in ['|', ')', None]:
                while stack[-1] == '+':
                    output.append(stack.pop())
                stack.append('+')
        else:
            output.append(x)
            while stack[-1] == '!':
                output.append(stack.pop())
            if next not in ['|', ')', None]:
                while stack[-1] == '+':
                    output.append(stack.pop())
                stack.append('+')

    while stack[-1] is not None:
        output.append(stack.pop())

    return output


def select_by_tags(query):
    """Return digests that match the query.

    Three operators are recognized:
    - Nothing (or whitespace) between tokens means 'AND';
    - '|' means 'OR';
    - '!' means NOT (unary).
    All other characters are considered parts of tokens (tags).

    query: a string query to match against

    return: a list of matching digests
    """
    stack = []
    all_files = files.keys()
    query = to_rpn(query)

    for x in query:
        if x == '|':
            stack.append(stack.pop() | stack.pop())
        elif x == '+':
            stack.append(stack.pop() & stack.pop())
        elif x == '!':
            stack.append(all_files - stack.pop())
        else:
            try:
                stack.append(set(tags[x]))
            except KeyError:
                stack.append(set())

    return list(stack.pop())


def cmd_add(filenames):
    """Perform 'add' command.

    Put files in storage and add their filename as first tag.

    Changes 'last' to contain the (int) digests of the files added.

    filenames: list of filenames; should be valid paths.
    """
    global last
    tmp_last = []

    for filename in filenames:
        sha3_digest = store(filename)

        name, ext = split_name_ext(filename)
        add_tag(sha3_digest, "name/" + name)
        if ext is not None:
            add_tag(sha3_digest, "ext/" + ext)

        tmp_last.append(sha3_digest)

    last = tuple(set(tmp_last))


def cmd_describe_files():
    """Perform 'describe-files' command.

    Write out a list of all files (as string digests) with their tags.

    Does not change 'last'. This behaviour is intended.
    """
    global files

    extensions = (get_ext(digest) for digest in files)
    extlen = max(len(ext) if ext is not None else 0 for ext in extensions) + 1

    for digest, tags in files.items():
        ext = get_ext(digest)
        if ext is not None:
            print("{} | {:^{extlen}} | {}".format(
                digest_to_str(digest), '.' + ext, ", ".join(tags),
                extlen=extlen))
        else:
            print("{} | {:{extlen}} | {}".format(
                digest_to_str(digest), '', ", ".join(tags),
                extlen=extlen))


def cmd_describe_tags():
    """Perform 'describe-tags' command.

    Write out a list of all tags with their files (as string digests).

    Does not change 'last'. This behaviour is intended.
    """
    global tags

    for tag, files in tags.items():
        str_dgs = [digest_to_str(digest) for digest in files]
        print("{:32}: {}".format(tag, ", ".join(hex_dgs)))


def cmd_tag(str_digests, new_tags):
    """Perform 'tag' command.

    Add tags to given files (string digests).

    Also accepts a special keyword 'last' to tag the most recently accessed
    files.
    Also accepts a special keyword 'all'. Will tag all currently stored files.

    Does not change 'last'.

    str_digests: string containing digests of the files that the tags should be
                 added to, delimited by commas.
                 OR keywords: 'last', 'all'.
    new_tags: iterable of tags that should be added to the file(s).
    """
    if str_digests == 'last':
        digests = last
    elif str_digests == 'all':
        digests = files.keys()
    else:
        digests = (str_to_digest(str_digest)
                   for str_digest in str_digests.split(','))

    for digest in digests:
        for tag in new_tags:
            add_tag(digest, tag)


def cmd_remove(str_digests):
    """Perform 'remove' command.

    Remove all tags from given files and delete them from storage.

    Also accepts a special keyword 'last' to remove the most recently accessed
    files.
    Also accepts a special keyword 'all'. Will remove all currently stored
    files.

    Does not change 'last'.

    str_digests: list of digests of files to remove.
                 OR keywords: 'last', 'all'.
    """
    if str_digests[0] == 'last':
        digests = last
    elif str_digests[0] == 'all':
        digests = files.keys()
    else:
        digests = (str_to_digest(str_digest)
                   for str_digest in str_digests)

    for digest in digests:
        unstore(digest)
        for t in files[digest].copy():
            del_tag(digest, t)
        files.pop(digest)


def cmd_untag(str_digests, del_tags):
    """Perform 'untag' command.

    Remove given tags from given files (string digests).

    Also accepts a special keyword 'last' to untag the most recently accessed
    files.
    Also accepts a special keyword 'all'. Will untag all currently stored
    files.

    Does not change 'last'.

    str_digests: string containing digests of the files that the tags should be
                 removed from, delimited by commas.
                 OR 'last' keyword.
    new_tags: iterable of tags that should be removed from the file(s).
    """
    if str_digests == 'last':
        digests = last
    elif str_digests == 'all':
        digests = files.keys()
    else:
        digests = (str_to_digest(str_digest)
                   for str_digest in str_digests.split(','))

    for digest in digests:
        for tag in del_tags:
            del_tag(digest, tag)


def cmd_list(queries):
    """Perform 'list' command.

    Print out all files that match the query. Query should be hard quoted
    (with single quotes) for your own good.

    Changes 'last' to contain the (int) digests of the files listed.

    Accepted query syntax is:
    - Nothing (or whitespace) between tokens means 'AND';
    - '|' means 'OR';
    - '!' means NOT (unary).
    All other characters are considered parts of tokens (tags).

    As you can see, some symbols are used that the shell also employs for
    it's own need. That's where hard quoting comes into play.

    Whitespace may be not quoted. For example, these invocations will
    produce identical results:
    - tagme-file list 'tag1 tag2 (tag3 | tag4) !tag5 !(tag6 | tag7)'
    - tagme-file list tag1 tag2 '(tag3 | tag4)' '!tag5 !(tag6 | tag7)'
    - tagme-file list tag1 tag2 \(tag3 \| tag4\) \!tag5 \!\(tag6 \| tag7 \)
    First approach is strongly recommended.

    queries: list of string queries.
    """
    global last
    tmp_last = []

    query = " ".join(queries)
    matches = select_by_tags(query)

    extensions = (get_ext(digest) for digest in matches)
    extlen = max(len(ext) if ext is not None else 0 for ext in extensions) + 1

    for digest in matches:
        ext = get_ext(digest)
        if ext is not None:
            print("{} | {:^{extlen}} | {}".format(
                digest_to_str(digest), '.' + ext, ", ".join(files[digest]),
                extlen=extlen))
        else:
            print("{} | {:{extlen}} | {}".format(
                digest_to_str(digest), '', ", ".join(files[digest]),
                extlen=extlen))


    last = tuple(set(matches))


def cmd_get(str_digests):
    """Perform 'get' command.

    Copy given files from storage to current directory.

    Also accepts a special keyword 'last' to remove the most recently accessed
    files.
    Also accepts a special keyword 'all'. Will remove all currently stored
    files.

    Does not change 'last'.

    str_digests: list of digests of files to remove.
                 OR keywords: 'last', 'all'.
    """
    if str_digests[0] == 'last':
        digests = last
    elif str_digests[0] == 'all':
        digests = files.keys()
    else:
        digests = (str_to_digest(str_digest)
                   for str_digest in str_digests)

    for digest in digests:
        copy_out(digest)


def cmd_select(queries):
    """Perform 'select' command.

    Copy all files that match the query to the current directory. Query should
    be hard quoted (with single quotes) for your own good.

    Changes 'last' to contain the (int) digests of the files copied.

    Accepted query syntax is:
    - Nothing (or whitespace) between tokens means 'AND';
    - '|' means 'OR';
    - '!' means NOT (unary).
    All other characters are considered parts of tokens (tags).

    As you can see, some symbols are used that the shell also employs for
    it's own need. That's where hard quoting comes into play.

    Whitespace may be not quoted. For example, these invocations will
    produce identical results:
    - tagme-file list 'tag1 tag2 (tag3 | tag4) !tag5 !(tag6 | tag7)'
    - tagme-file list tag1 tag2 '(tag3 | tag4)' '!tag5 !(tag6 | tag7)'
    - tagme-file list tag1 tag2 \(tag3 \| tag4\) \!tag5 \!\(tag6 \| tag7 \)
    First approach is strongly recommended.

    queries: list of string queries.
    """
    global last
    tmp_last = []

    query = " ".join(queries)
    matches = select_by_tags(query)
    for digest in matches:
        copy_out(digest)

    last = tuple(set(matches))


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
    elif cmd == "list":
        cmd_list(sys.argv[2:])
    elif cmd == "get":
        cmd_get(sys.argv[2:])
    elif cmd == "select":
        cmd_select(sys.argv[2:])

    pickle.dump(files, open(FILES, "wb"))
    pickle.dump(tags, open(TAGS, "wb"))
    pickle.dump(last, open(LAST, "wb"))


if __name__ == "__main__":
    main()
