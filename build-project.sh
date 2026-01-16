#!/bin/bash
set -e

HDFS_VERSION=$1

mvn clean install -Pdist,web-ui,withDocker,hadoop-"${HDFS_VERSION}" -DskipTests