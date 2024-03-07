from merge_branches import FINAL_BRANCH, MERGE_PATHS_FILE, load_merge_paths


def test_linear_path():
    merge_paths = load_merge_paths()

    src_dst_iter = iter(merge_paths.items())
    (oldest_branch, prev_dst_branch) = next(src_dst_iter)
    assert (
        oldest_branch not in merge_paths.values()
    ), f"Oldest branch '{oldest_branch}' cannot be a destination branch."

    for src_branch, dst_branch in src_dst_iter:
        assert (
            prev_dst_branch == src_branch
        ), (
            f"Since the merge graph is linear, the source branch '{src_branch}' must be the same "
            f"as the previous destination branch, which is '{prev_dst_branch}'. Check out "
            f"{MERGE_PATHS_FILE}."
        )
        prev_dst_branch = dst_branch

    assert (
        prev_dst_branch == FINAL_BRANCH
    ), f"The last destination is '{prev_dst_branch}' but must be '{FINAL_BRANCH}'."
