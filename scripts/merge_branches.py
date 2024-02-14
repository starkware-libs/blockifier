#!/usr/bin/env python3.9

"""
Merge a branch into another branch. Example usage:
```
scripts/merge_branches.py --src main-v0.13.0
```
"""

import argparse
import json
import os
import subprocess
from typing import Dict, List, Optional

FINAL_BRANCH = "main"
MERGE_PATHS_FILE = "scripts/merge_paths.json"


def load_merge_paths() -> Dict[str, str]:
    return json.load(open(MERGE_PATHS_FILE))


def run_command(command: str, allow_error: bool = False) -> List[str]:
    """
    Runs a bash command and returns the output as a list of lines.
    """
    try:
        command_output = (
            subprocess.check_output(command, shell=True, cwd=os.getcwd())
            .decode("utf-8")
            .splitlines()
        )
        output_lines = "\n".join(command_output)
        print(f"Command '{command}' output:\n{output_lines}")
        return command_output
    except subprocess.CalledProcessError as error:
        if not allow_error:
            raise
        print(f"Command '{command}' hit error: {error=}.")
        return str(error).splitlines()


def get_dst_branch(src_branch: str, dst_branch_override: Optional[str]) -> str:
    if dst_branch_override is not None:
        return dst_branch_override
    assert (
        src_branch.replace("origin/", "") != FINAL_BRANCH
    ), f"{FINAL_BRANCH} has no default destination branch."

    return load_merge_paths()[src_branch]


def srcdiff(source_branch: str, destination_branch: Optional[str], files: List[str]):
    destination_branch = get_dst_branch(
        src_branch=source_branch, dst_branch_override=destination_branch
    )
    files_line = " ".join(files)
    run_command(
        f"git diff $(git merge-base origin/{source_branch} origin/{destination_branch}) "
        f"origin/{source_branch} {files_line}"
    )


def dstdiff(source_branch: str, destination_branch: Optional[str], files: List[str]):
    destination_branch = get_dst_branch(
        src_branch=source_branch, dst_branch_override=destination_branch
    )
    files_line = " ".join(files)
    run_command(
        f"git diff $(git merge-base origin/{source_branch} origin/{destination_branch}) "
        f"origin/{destination_branch} {files_line}"
    )


def merge_branches(src_branch: str, dst_branch: Optional[str]):
    """
    Merge source branch into destination branch.
    If no destination branch is passed, the destination branch is taken from state on repo.
    """
    user = os.environ["USER"]
    dst_branch = get_dst_branch(src_branch=src_branch, dst_branch_override=dst_branch)

    merge_branch = f"{user}/merge-{src_branch}-into-{dst_branch}"
    print(f"Source branch: {src_branch}")
    print(f"Destination branch: {dst_branch}\n")

    run_command("git fetch")
    run_command(f"git checkout origin/{dst_branch}")
    run_command(f"git checkout -b {merge_branch}")
    print("Merging...")
    run_command("git config merge.conflictstyle diff3")

    run_command(f"git merge origin/{src_branch}", allow_error=True)

    run_command("git config --unset merge.conflictstyle")
    run_command("git status -s | grep \"^UU\" | awk '{ print $2 }' | tee /tmp/conflicts")

    conflicts_file = "/tmp/conflicts"
    conflicts = [line.strip() for line in open(conflicts_file).readlines() if line.strip() != ""]
    conflict_line = " ".join(conflicts)
    run_command(f"git add {conflict_line}", allow_error=True)
    run_command("git add changed_files/*", allow_error=True)
    print("Committing conflicts...")
    if len(conflicts) == 0:
        run_command(
            f'git commit --allow-empty -m "No conflicts in {src_branch} -> {dst_branch} merge, '
            'this commit is for any change needed to pass the CI."'
        )
    else:
        run_command(f'git commit -m "chore: merge branch {src_branch} into {dst_branch} (with conflicts)"')

    print("Pushing...")
    run_command(f"git push --set-upstream origin {merge_branch}")
    (merge_base,) = run_command(f"git merge-base origin/{src_branch} origin/{dst_branch}")

    print("Creating PR...")
    run_command(
        f'gh pr create --base {dst_branch} --title "Merge {src_branch} into {dst_branch}" '
        '--body ""'
    )

    if len(conflicts) != 0:
        compare = "https://github.com/starkware-libs/blockifier/compare"
        comment_file_path = "/tmp/comment.XXXXXX"
        with open(comment_file_path, "w") as comment_file:
            for conflict in conflicts:
                (filename_hash,) = run_command(f"echo -n {conflict} | sha256sum | cut -d' ' -f1")
                comment_file.write(
                    f"[Src]({compare}/{merge_base}..{src_branch}#diff-{filename_hash}) "
                    f"[Dst]({compare}/{merge_base}..{dst_branch}#diff-{filename_hash}) "
                    f"{conflict}\n"
                )
        run_command(f"gh pr comment -F {comment_file_path}")
        os.remove(comment_file_path)

    os.remove(conflicts_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Merge a branch into another branch.")
    parser.add_argument("--src", type=str, help="The source branch to merge.")
    parser.add_argument(
        "--dst",
        type=str,
        default=None,
        help=(
            "The destination branch to merge into. If no branch explicitly provided, uses the "
            f"destination branch registered for the source branch in {MERGE_PATHS_FILE}."
        ),
    )
    args = parser.parse_args()

    merge_branches(src_branch=args.src, dst_branch=args.dst)
