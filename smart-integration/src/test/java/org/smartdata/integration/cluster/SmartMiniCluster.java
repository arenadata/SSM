/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.smartdata.integration.cluster;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.hdfs.DFSConfigKeys;
import org.apache.hadoop.hdfs.DFSUtil;
import org.apache.hadoop.hdfs.MiniDFSCluster;
import org.apache.hadoop.hdfs.server.balancer.TestBalancer;
import org.apache.hadoop.metrics2.lib.DefaultMetricsSystem;
import org.smartdata.conf.SmartConf;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.hadoop.filesystem.SmartFileSystem;
import org.smartdata.hdfs.MiniClusterFactory;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.apache.hadoop.hdfs.DFSConfigKeys.DFS_NAMENODE_HTTP_ADDRESS_KEY;

/**
 * A MiniCluster for integration test.
 */
public class SmartMiniCluster implements SmartCluster {
  private MiniDFSCluster cluster;
  private FileSystem fileSystem;

  private static final int DEFAULT_BLOCK_SIZE = 100;

  static {
    TestBalancer.initTestSetup();
  }

  private void initConf(Configuration conf) {
    conf.setLong(DFSConfigKeys.DFS_BLOCK_SIZE_KEY, DEFAULT_BLOCK_SIZE);
    conf.setInt(DFSConfigKeys.DFS_BYTES_PER_CHECKSUM_KEY, DEFAULT_BLOCK_SIZE);
    conf.setLong(DFSConfigKeys.DFS_HEARTBEAT_INTERVAL_KEY, 1L);
    conf.setLong(DFSConfigKeys.DFS_BALANCER_MOVEDWINWIDTH_KEY, 2000L);
    conf.set("fs.hdfs.impl", SmartFileSystem.class.getName());
  }

  @Override
  public void setUp(SmartConf smartConf) throws Exception {
    initConf(smartConf);
    cluster = MiniClusterFactory.get().createWithStorages(3, smartConf);
    cluster.waitActive();
    Collection<URI> namenodes = DFSUtil.getInternalNsRpcUris(smartConf);
    List<URI> uriList = new ArrayList<>(namenodes);
    smartConf.set(DFS_NAMENODE_HTTP_ADDRESS_KEY, uriList.get(0).toString());
    smartConf.set(SmartConfKeys.SMART_DFS_NAMENODE_RPCSERVER_KEY,
        uriList.get(0).toString());
    fileSystem = new SmartFileSystem();
    fileSystem.initialize(cluster.getURI(), smartConf);
  }

  @Override
  public void cleanUp() throws IOException {
    if (cluster != null) {
      cluster.shutdown();
    }
    if (fileSystem != null) {
      fileSystem.close();
    }
    // clear registered metric systems of name- and datanodes
    DefaultMetricsSystem.instance().shutdown();
  }

  @Override
  public FileSystem getFileSystem() {
    return fileSystem;
  }
}
