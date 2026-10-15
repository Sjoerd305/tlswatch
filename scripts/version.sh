#!/bin/sh
# Prints the build version, without anyone having to choose one.
#
#   v0.2.0                  built exactly on a tag
#   v0.2.0-5-g5efacf7       five commits past the nearest tag
#   2026.10.15-5efacf7      no tag yet: the commit date and hash
#   ...-dirty               the working tree had uncommitted changes
#   dev                     not a git checkout
#
# The Makefile and the Dockerfile both use it, so a local build and a
# `docker compose up --build` report the same thing.
set -e
if v=$(git describe --tags --dirty 2>/dev/null); then
	echo "$v"
	exit 0
fi
if hash=$(git rev-parse --short=7 HEAD 2>/dev/null); then
	date=$(git log -1 --format=%cd --date=format:%Y.%m.%d)
	dirty=""
	git diff --quiet HEAD -- 2>/dev/null || dirty="-dirty"
	echo "$date-$hash$dirty"
	exit 0
fi
echo dev
