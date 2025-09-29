#!/usr/bin/env bash

set -euo pipefail

VERSION="$1"
NEXT_VERSION="$2"

if git tag | grep "${VERSION}"; then
  echo "Tag v${VERSION} already exists, bailing out"
  exit 1
fi

./mvnw versions:set -DgenerateBackupPoms=false -DnewVersion="$VERSION"
# macos sed
sed -i '' -e "s/<version>.*<\\/version>/<version>${VERSION}<\\/version>/g" README.md
sed -i '' -e "s/:[0-9]\\.[0-9]\\.[0-9]/:${VERSION}/g" README.md
git commit \
  --include "README.md" \
  --include "pom.xml" \
  --include "**/pom.xml" \
  --signoff \
  --message "Release version ${VERSION}"
git tag \
  --annotate "v${VERSION}" \
  --message "Release version ${VERSION}"

./mvnw versions:set -DgenerateBackupPoms=false -DnewVersion="${NEXT_VERSION}-SNAPSHOT"
git commit \
  --include "README.md" \
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
