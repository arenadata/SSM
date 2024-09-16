#!/bin/bash
set -e

SSM_APP_VERSION=$(mvn -q -Dexec.executable=echo -Dexec.args='${project.version}' --non-recursive exec:exec)
SSM_APP_VERSION=$(echo "${SSM_APP_VERSION}" | head -1)
SSM_SERVER_IMAGE_VERSION=${SSM_APP_VERSION:-*}

while [ $# -gt 0 ]; do
  case "$1" in
    --cluster=*)
      CLUSTER_TYPE="${1#*=}"
      ;;
    --hadoop=*)
      HADOOP_PROFILE="${1#*=}"
      ;;
    *)
      echo "=========================================================="
      echo " Error: Invalid argument. Should be in the form --key=arg."
      echo " Supported arguments:"
      echo "    --cluster: multihost (default) | singlehost"
      echo "    --hadoop: 3.3 (default)"
      echo "=========================================================="
      exit 1
  esac
  shift
done

CLUSTER_TYPE=${CLUSTER_TYPE:-multihost}
HADOOP_PROFILE=${HADOOP_PROFILE:-3.3}

case $HADOOP_PROFILE in
  3.3)
  HADOOP_VERSION=3.3.6
  ;;
  *)
    echo "Unknown Hadoop profile ${HADOOP_PROFILE}"
    exit 1;
  ;;
esac

if type -p java; then
    echo found java executable in PATH
    _java=java
elif [[ -n "$JAVA_HOME" ]] && [[ -x "$JAVA_HOME/bin/java" ]];  then
    echo found java executable in JAVA_HOME
    _java="$JAVA_HOME/bin/java"
else
    echo "ERROR: no java"
    exit 1
fi

if [[ "$_java" ]]; then
    version=$("$_java" -version 2>&1 | awk -F '"' '/version/ {print $2}')
    echo version "$version"
    if [[ "$version" != "1.8"* ]]; then
        echo "ERROR: java must be 1.8+ version"
        exit 1
    fi
fi

echo "=============================="
echo "      Rebuild the project     "
echo "=============================="
mvn clean package -Pdist,web-ui,hadoop-${HADOOP_PROFILE} -DskipTests

echo "========================================================"
echo "      Build Hadoop ${HADOOP_VERSION} with SSM image     "
echo "========================================================"

case $CLUSTER_TYPE in
  singlehost)
    docker build -f ./supports/tools/docker/singlehost/Dockerfile -t cloud-hub.adsw.io/library/ssm-hadoop:${HADOOP_VERSION} \
    --build-arg="SSM_APP_VERSION=${SSM_APP_VERSION}" \
    --build-arg="HADOOP_VERSION=${HADOOP_VERSION}" .
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
