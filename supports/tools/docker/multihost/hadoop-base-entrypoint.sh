#!/bin/bash

. ./common.sh

# Set some sensible defaults
export CORE_CONF_fs_defaultFS=${CORE_CONF_fs_defaultFS:-hdfs://$(hostname -f):8020}

configure "$HADOOP_CONF_DIR"/core-site.xml core CORE_CONF
configure "$HADOOP_CONF_DIR"/hdfs-site.xml hdfs HDFS_CONF
configure "$HADOOP_CONF_DIR"/yarn-site.xml yarn YARN_CONF
configure "$HADOOP_CONF_DIR"/httpfs-site.xml httpfs HTTPFS_CONF
configure "$HADOOP_CONF_DIR"/kms-site.xml kms KMS_CONF
configure "$HADOOP_CONF_DIR"/mapred-site.xml mapred MAPRED_CONF

# shellcheck disable=SC2068
exec $@