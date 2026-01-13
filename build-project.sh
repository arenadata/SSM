#!/bin/bash
set -e

HDFS_VERSION=$1

mvn install:install-file -pl smart-tests -Dos.arch=x86_64
mvn clean install -Pdist,web-ui,hadoop-"${HDFS_VERSION}" -DskipTests -Dos.arch=x86_64