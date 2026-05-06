#!/bin/bash

. ./common.sh

SSM_RUNTIME_CONF_DIR=/tmp/ssm-conf
rm -rf "$SSM_RUNTIME_CONF_DIR"
mkdir -p "$SSM_RUNTIME_CONF_DIR"
cp -R "$SSM_HOME"/conf/. "$SSM_RUNTIME_CONF_DIR"/
cp "$SSM_HOME"/smart-site.xml "$SSM_RUNTIME_CONF_DIR"/smart-site.xml

cp /root/.ssh/id_rsa /tmp/shared/id_rsa
cp /root/.ssh/id_rsa.pub /tmp/shared/id_rsa.pub
service ssh start
ssh-keyscan "$HOSTNAME" >> /root/.ssh/known_hosts
echo "export JAVA_HOME=${JAVA_HOME}" >> /root/.bashrc
echo "export SMART_HOME=${SSM_HOME}" >> /root/.bashrc
echo "export SMART_CONF_DIR=${SSM_RUNTIME_CONF_DIR}/" >> /root/.bashrc

# Starting Smart Storage Manager
cd $SSM_HOME || exit

echo "---------------------------"
echo "Starting SSM server and agents"
echo "---------------------------"

wait_for_file /etc/secrets/ssm.keytab
wait_for_file /etc/secrets/http.keytab
wait_for_it ssm-metastore-db.demo:5432
wait_for_it samba:389
wait_for_it hadoop-namenode.demo:8020
wait_for_it hadoop-datanode.demo:22

source bin/start-ssm.sh ${SSM_DEBUG_OPT} --config ${SSM_RUNTIME_CONF_DIR}/ &
wait_for_it $(hostname -f):8081
wait_for_it hadoop-datanode.demo:7048

tail -f /var/log/ssm/*
