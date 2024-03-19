#!/usr/bin/env bash
echo "Get configuration from config."
. config
# for python use
sudo -su hdfs hdfs dfs -rm -r -skipTrash ${BASE_DIR}