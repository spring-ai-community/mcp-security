#!/usr/bin/env bash

set -euo pipefail

VERSION="$1"
NEXT_VERSION="$2"

./mvnw versions:set -DgenerateBackupPoms=false -DnewVersion="$VERSION"
git commit \
  --include "pom.xml" \
  --include "**/pom.xml" \
  --signoff \
  --message "Release version ${VERSION}"
git tag \
  --annotate "v${VERSION}" \
  --message "Release version ${VERSION}"

./mvnw versions:set -DgenerateBackupPoms=false -DnewVersion="${NEXT_VERSION}-SNAPSHOT"
git commit \
  --include "pom.xml" \
  --include "**/pom.xml" \
  --signoff \
  --message "Next development version"

echo "Please inspect your commits before moving forward."
echo
read -p "Are you sure you want to continue? [yN]" -n 1 -r
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
  git push
  git push --tags
fi
