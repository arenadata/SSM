#!/bin/bash

. ./common.sh

cp /root/.ssh/id_rsa /tmp/shared/id_rsa
cp /root/.ssh/id_rsa.pub /tmp/shared/id_rsa.pub
service ssh start
ssh-keyscan "$HOSTNAME" >> /root/.ssh/known_hosts
echo "export JAVA_HOME=${JAVA_HOME}" >> /root/.bashrc
echo "export SMART_HOME=${SSM_HOME}" >> /root/.bashrc
echo "export SMART_CONF_DIR=${SSM_HOME}/conf/" >> /root/.bashrc

# Starting Smart Storage Manager
cd $SSM_HOME || exit

echo "---------------------------"
echo "Starting SSM server and agents"
echo "---------------------------"

source bin/start-ssm.sh --config ${SSM_HOME}/conf/ &
wait_for_it $(hostname -f):8081
wait_for_it hadoop-datanode.demo:7048

tail -f /var/log/ssm/*