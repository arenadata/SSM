#!/bin/bash

. ./common.sh

cp /root/.ssh/id_rsa /tmp/shared/id_rsa
cp /root/.ssh/id_rsa.pub /tmp/shared/id_rsa.pub
service ssh start
ssh-keyscan "$HOSTNAME" >> /root/.ssh/known_hosts
echo "export JAVA_HOME=${JAVA_HOME}" >> /root/.bashrc

# Starting Smart Storage Manager
cd $SSM_HOME || exit

echo "---------------------------"
echo "Starting SSM server locally"
echo "---------------------------"

source bin/start-ssm.sh --config conf/ &
wait_for_it $(hostname -f):8081

echo "-------------------"
echo "Starting SSM agents"
echo "-------------------"

source bin/start-agent.sh &
wait_for_it hadoop-datanode:7048

tail -f /var/log/ssm/*