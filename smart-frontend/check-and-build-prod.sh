#!/bin/sh

set -e

CURRENT_HASH="$(find ./app -type f -print0 | sort -z | xargs -0 sha1sum | sha1sum)"
if test -f hash.txt; then
  PREV_HASH="$(cat hash.txt)"
fi

if  test -f "build/index.html"; then
  if [ "$PREV_HASH" = "$CURRENT_HASH" ]; then
    echo "\033[0;90mWeb app has not changed\033[0m"
  else
    CURDIR=$(dirname "$0")
    echo "\033[0;32mWeb app has changed\033[0m"
    docker run -i --rm -v $CURDIR/build:/wwwroot -v $CURDIR/app:/app -w /app node:20.9.0-alpine ./build.sh
    if [ -d "build" ]; then
      echo "\033[0;34mWeb app has been built\033[0m"
      echo "$CURRENT_HASH" >hash.txt
    else
      echo "\033[0;31mWeb app has not been built\033[0m"
    fi
  fi
else
  echo "\033[0;31mWeb app has not been built\033[0m"
  CURDIR=$(dirname "$0")
  docker run -i --rm -v $CURDIR/build:/wwwroot -v $CURDIR/app:/app -w /app node:20.9.0-alpine ./build.sh
  if [ -d "build" ]; then
    echo "\033[0;34mWeb app has been built\033[0m"
    echo "$CURRENT_HASH" >hash.txt
  else
    echo "\033[0;31mWeb app has not been built\033[0m"
  fi
fi
