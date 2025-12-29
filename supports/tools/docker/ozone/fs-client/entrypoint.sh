#!/bin/bash

. ./common.sh

echo "export JAVA_HOME=${JAVA_HOME}" >> /root/.bashrc

cp /etc/jars/*.jar $HADOOP_HOME/share/hadoop/common/lib/
moveHadoopConfFiles /etc/conf ${HADOOP_CONF_DIR}

tail -f /dev/null