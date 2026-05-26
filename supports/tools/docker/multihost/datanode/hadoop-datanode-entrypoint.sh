#!/bin/bash

. ./common.sh

SSM_RUNTIME_CONF_DIR=/tmp/ssm-conf
rm -rf "$SSM_RUNTIME_CONF_DIR"
mkdir -p "$SSM_RUNTIME_CONF_DIR"
cp -R /opt/ssm/conf/. "$SSM_RUNTIME_CONF_DIR"/
cp /opt/ssm/smart-site.xml "$SSM_RUNTIME_CONF_DIR"/smart-site.xml

cp /etc/ssm/shared/id_rsa /root/.ssh/id_rsa
cp /etc/ssm/shared/id_rsa.pub /root/.ssh/id_rsa.pub
cat /root/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys
service ssh start
ssh-keyscan ssm-server.demo >> /root/.ssh/known_hosts
echo "export JAVA_HOME=${JAVA_HOME}" >> /root/.bashrc
echo "export SMART_CONF_DIR=${SSM_RUNTIME_CONF_DIR}/" >> /root/.bashrc

wait_for_file /etc/secrets/datanode.keytab
wait_for_file /etc/secrets/agent.keytab
wait_for_file /etc/secrets/http.keytab

datadir=`echo $HDFS_CONF_dfs_datanode_data_dir | perl -pe 's#file://##'`
if [ ! -d $datadir ]; then
  echo "Datanode data directory not found: $datadir"
  exit 2
fi

chmod +r /etc/secrets/*.keytab

moveHadoopConfFiles /etc/conf ${HADOOP_CONF_DIR}
configure "$HADOOP_CONF_DIR"/hdfs-site.xml hdfs HDFS_CONF

$HADOOP_HOME/bin/hdfs --debug --config $HADOOP_CONF_DIR datanode

tail -f /dev/null
