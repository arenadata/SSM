#!/bin/bash

cp /etc/ssm/shared/id_rsa /root/.ssh/id_rsa
cp /etc/ssm/shared/id_rsa.pub /root/.ssh/id_rsa.pub
cat /root/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys
service ssh start
ssh-keyscan ssm-server >> /root/.ssh/known_hosts
echo "export JAVA_HOME=${JAVA_HOME}" >> /root/.bashrc

datadir=`echo $HDFS_CONF_dfs_datanode_data_dir | perl -pe 's#file://##'`
if [ ! -d $datadir ]; then
  echo "Datanode data directory not found: $datadir"
  exit 2
fi

$HADOOP_HOME/bin/hdfs --config $HADOOP_CONF_DIR datanode

tail -f /dev/null