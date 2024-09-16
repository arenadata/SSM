#!/bin/bash
set -e

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

HADOOP_PROFILE=${HADOOP_PROFILE:-3.3}
CLUSTER_TYPE=${CLUSTER_TYPE:-multihost}

case $HADOOP_PROFILE in
  3.3)
  HADOOP_VERSION=3.3.6
  ;;
  *)
    echo "Unknown Hadoop profile ${HADOOP_PROFILE}"
    exit 1;
  ;;
esac

case $CLUSTER_TYPE in
  singlehost)
    COMPOSE_FILE_PATH="./singlehost/docker-compose.yaml"
  ;;
  multihost)
    COMPOSE_FILE_PATH="./multihost/docker-compose.yaml"
  ;;
  *)
    echo "Unknown cluster type ${CLUSTER_TYPE}"
    exit 1;
  ;;
esac

env HADOOP_VERSION=$HADOOP_VERSION docker compose -f ${COMPOSE_FILE_PATH} up -d