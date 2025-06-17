#!/bin/bash
set -e

HDFS_VERSION=$1

mvn install:install-file -pl smart-tests
mvn clean install -Pdist,web-ui,hadoop-"${HDFS_VERSION}" -DskipTests