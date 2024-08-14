#!/bin/bash

SSM_APP_VERSION=$(mvn -q -Dexec.executable=echo -Dexec.args='${project.version}' --non-recursive exec:exec)
SSM_APP_VERSION=$(echo "${SSM_APP_VERSION}" | head -1)
SSM_SERVER_IMAGE_VERSION=${SSM_APP_VERSION%-*}
HADOOP_VERSION=3.2.4
HADOOP_PROFILE=3.2
CLUSTER_TYPE=$1

if [ -z "$CLUSTER_TYPE" ]
then
  CLUSTER_TYPE=multihost
fi

echo "=============================="
echo "      Rebuild the project     "
echo "=============================="
mvn clean package -Pdist,web,hadoop-${HADOOP_PROFILE} -DskipTests

echo "========================================================"
echo "      Build Hadoop ${HADOOP_VERSION} with SSM image     "
echo "========================================================"

case $CLUSTER_TYPE in
  singlehost)
    docker build -f ./supports/tools/docker/singlehost/Dockerfile -t cloud-hub.adsw.io/library/ssm-hadoop:${HADOOP_VERSION} --build-arg="SSM_APP_VERSION=${SSM_APP_VERSION}" .
  ;;
  multihost)
    docker build -f ./supports/tools/docker/multihost/Dockerfile-hadoop-base -t cloud-hub.adsw.io/library/hadoop-base:${HADOOP_VERSION} \
    --build-arg="HADOOP_VERSION=${HADOOP_VERSION}" \
    --build-arg="SSM_APP_VERSION=${SSM_APP_VERSION}" .

    docker build -f ./supports/tools/docker/multihost/datanode/Dockerfile-hadoop-datanode -t cloud-hub.adsw.io/library/hadoop-datanode:${HADOOP_VERSION} .

    docker build -f ./supports/tools/docker/multihost/namenode/Dockerfile-hadoop-namenode -t cloud-hub.adsw.io/library/hadoop-namenode:${HADOOP_VERSION} .
    docker build -f ./supports/tools/docker/multihost/ssm/Dockerfile-ssm-server -t cloud-hub.adsw.io/library/ssm-server:"${SSM_SERVER_IMAGE_VERSION}" \
    --build-arg="SSM_APP_VERSION=${SSM_APP_VERSION}" .
  ;;
  *)
    echo "Unknown cluster type ${CLUSTER_TYPE}"
    exit 1;
  ;;
esac
