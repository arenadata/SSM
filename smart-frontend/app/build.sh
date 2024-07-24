#!/bin/sh

# Set Yarn version
YARN_VERSION=4.1.1

yarn set version $YARN_VERSION
yarn install
yarn build --mode production --outDir /wwwroot
