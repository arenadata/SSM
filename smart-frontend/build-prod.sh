#!/bin/sh

CURDIR=$(dirname "$0")

docker run -i --rm -v $CURDIR/build:/wwwroot -v $CURDIR/app:/app -w /app node:20.9.0-alpine ./build.sh
