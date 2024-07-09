#!/bin/bash

set -e

# Usage:
# scripts/generate_changelog.sh <FROM_TAG> <TO_TAG>

# Install git-cliff if missing.
GIT_CLIFF_VERSION="2.4.0"
cargo install --list | grep -q "git-cliff v${GIT_CLIFF_VERSION}" || cargo install git-cliff@${GIT_CLIFF_VERSION}

# Combine dev tags into the next RC / stable tag.
git-cliff $1..$2 -o changelog_$1_$2.md --ignore-tags ".*-dev.[0-9]+"
