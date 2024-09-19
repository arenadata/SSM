#!/usr/bin/env bash

# Check namenode
curl -f http://hadoop-namenode.demo:9870/ || exit 1

# Check resource manager
curl -f http://hadoop-namenode.demo:8088/ || exit 1

# Check node manager
curl -f http://hadoop-namenode.demo:8042/ || exit 1
