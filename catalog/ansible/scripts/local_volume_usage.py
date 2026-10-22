"""Bounded read-only accounting of one module-observed local volume mountpoint."""

import argparse
import json
import os
import stat
import time


def capacity(path):
    """Return nullable allocated/free bytes without following filesystem links."""
    unknown = {"observed_used_bytes": None, "observed_free_bytes": None}
    if not os.path.isabs(path):
        return unknown
    descriptors = set()
    deadline = time.monotonic() + 2
    free = None
    try:
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        descriptors.add(root)
        for component in path.split("/"):
            if not component:
                continue
            if component in (".", "..") or time.monotonic() >= deadline:
                return unknown
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=root)
            descriptors.add(child)
            os.close(root)
            descriptors.remove(root)
            root = child
        filesystem = os.fstatvfs(root)
        free = filesystem.f_bavail * filesystem.f_frsize
        used, entries, visited = 0, 0, set()
        pending = [root]
        while pending:
            current = pending.pop()
            with os.scandir(current) as children:
                for entry in children:
                    entries += 1
                    if entries > 100000 or time.monotonic() >= deadline:
                        return {"observed_used_bytes": None, "observed_free_bytes": free}
                    metadata = entry.stat(follow_symlinks=False)
                    key = (metadata.st_dev, metadata.st_ino)
                    if key in visited:
                        continue
                    visited.add(key)
                    if stat.S_ISREG(metadata.st_mode):
                        used += metadata.st_blocks * 512
                    elif stat.S_ISDIR(metadata.st_mode):
                        if len(descriptors) >= 255:
                            return {"observed_used_bytes": None, "observed_free_bytes": free}
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                        dir_fd=current)
                        descriptors.add(child)
                        actual = os.fstat(child)
                        if (actual.st_dev, actual.st_ino) != key:
                            return {"observed_used_bytes": None, "observed_free_bytes": free}
                        pending.append(child)
            os.close(current)
            descriptors.remove(current)
        return {"observed_used_bytes": used, "observed_free_bytes": free}
    except OSError:
        return {"observed_used_bytes": None, "observed_free_bytes": free}
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def main():
    """Accept a native mountpoint and print only nullable capacity facts."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mountpoint")
    args = parser.parse_args()
    print(json.dumps(capacity(args.mountpoint), separators=(",", ":")))


if __name__ == "__main__":
    main()
