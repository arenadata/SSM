#!/bin/bash

. ./common.sh

service ssh start
ssh-keyscan ssm-server >> /root/.ssh/known_hosts
echo "export JAVA_HOME=${JAVA_HOME}" >> /root/.bashrc

namedir=`echo $HDFS_CONF_dfs_namenode_name_dir | perl -pe 's#file://##'`
if [ ! -d $namedir ]; then
  echo "Namenode name directory not found: $namedir"
  exit 2
fi

if [ -z "$CLUSTER_NAME" ]; then
  echo "Cluster name not specified"
  exit 2
fi

# HDFS
addProperty "$HADOOP_CONF_DIR"/hdfs-site.xml dfs.namenode.rpc-bind-host 0.0.0.0
addProperty "$HADOOP_CONF_DIR"/hdfs-site.xml dfs.namenode.servicerpc-bind-host 0.0.0.0
addProperty "$HADOOP_CONF_DIR"/hdfs-site.xml dfs.namenode.http-bind-host 0.0.0.0
addProperty "$HADOOP_CONF_DIR"/hdfs-site.xml dfs.namenode.https-bind-host 0.0.0.0
addProperty "$HADOOP_CONF_DIR"/hdfs-site.xml dfs.client.use.datanode.hostname true
addProperty "$HADOOP_CONF_DIR"/hdfs-site.xml dfs.datanode.use.datanode.hostname true

# YARN
addProperty "$HADOOP_CONF_DIR"/yarn-site.xml yarn.resourcemanager.bind-host 0.0.0.0
addProperty "$HADOOP_CONF_DIR"/yarn-site.xml yarn.nodemanager.bind-host 0.0.0.0
addProperty "$HADOOP_CONF_DIR"/yarn-site.xml yarn.timeline-service.bind-host 0.0.0.0

# MAPRED
addProperty "$HADOOP_CONF_DIR"/mapred-site.xml yarn.nodemanager.bind-host 0.0.0.0

echo "--------------"
echo "format namenode"
echo "--------------"
if [ "`ls -A $namedir`" == "" ]; then
  echo "Formatting namenode name directory: $namedir"
  $HADOOP_HOME/bin/hdfs --config $HADOOP_CONF_DIR namenode -format $CLUSTER_NAME
fi

echo "--------------"
echo "Start namenode"
echo "--------------"
$HADOOP_HOME/bin/hdfs --config $HADOOP_CONF_DIR namenode &
wait_for_it $(hostname -f):9870

echo "------------------"
echo "Start node manager"
echo "------------------"
$HADOOP_HOME/bin/yarn --config $HADOOP_CONF_DIR nodemanager &
wait_for_it $(hostname -f):8042

echo "----------------------"
echo "Start resource manager"
echo "----------------------"
$HADOOP_HOME/bin/yarn --config $HADOOP_CONF_DIR resourcemanager &
wait_for_it $(hostname -f):8088

tail -f /dev/null