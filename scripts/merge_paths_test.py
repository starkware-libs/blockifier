#!/usr/bin/env python3.9

import sys

from merge_branches import FINAL_BRANCH, MERGE_PATHS_FILE, load_merge_paths


def verify_linear_path():
    merge_paths = load_merge_paths()

    src_dst_iter = iter(merge_paths.items())
    (_, prev_dst_branch) = next(src_dst_iter)
    for src_branch, dst_branch in src_dst_iter:
        if prev_dst_branch != src_branch:
            print(
                f"Since the merge graph is linear, the source branch '{src_branch}' must be the "
                f"same as the previous destination branch, which is '{prev_dst_branch}'. Check "
                f"out {MERGE_PATHS_FILE}."
            )
            sys.exit(1)
        prev_dst_branch = dst_branch

    if prev_dst_branch != FINAL_BRANCH:
        print(f"The last destination is {prev_dst_branch} but must be {FINAL_BRANCH}.")
        sys.exit(1)


if __name__ == "__main__":
    verify_linear_path()
    sys.exit(0)
