#!/usr/bin/env python3.9

import json
import os
import subprocess
from datetime import datetime

DIR = os.path.dirname(__file__)
MERGE_PATHS_FILE = os.path.join(DIR, "merge_paths.json")
BASH_COLORS = {
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "white": "97",
    "cyan": "96",
}


def color_txt(color, txt: str, bold: bool = True):
    bold_str = "1;" if bold else ""
    color_code = BASH_COLORS[color.lower()]
    lines = txt.splitlines()
    return "\n".join(f"\033[{bold_str}{color_code}m{line}\033[0m" for line in lines)


def main():
    merge_paths = json.load(open(MERGE_PATHS_FILE))
    for branch, merge_into in merge_paths.items():
        # Get the list of timestamps of unmerged commits.
        unmerged_commits_timestamps = list(
            map(
                int,
                subprocess.check_output(
                    [
                        "git",
                        "log",
                        f"origin/{merge_into}..origin/{branch}",
                        "--format=format:%ct",
                    ]
                )
                .decode("utf8")
                .strip()
                .splitlines(),
            )
        )

        if len(unmerged_commits_timestamps) == 0:
            status = color_txt("green", "Up to date")
        else:
            last_unmerged_commit_time = datetime.fromtimestamp(min(unmerged_commits_timestamps))
            unmerged_days = (datetime.now() - last_unmerged_commit_time).days
            status = f"{unmerged_days} days"
            if unmerged_days > 7:
                status = color_txt("red", status)

        print(f"{branch}-->{merge_into}".ljust(40), status)


if __name__ == "__main__":
    main()
