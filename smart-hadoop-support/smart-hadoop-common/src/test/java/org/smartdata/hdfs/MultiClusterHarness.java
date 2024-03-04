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
package org.smartdata.hdfs;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.DFSClient;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.hdfs.MiniDFSCluster;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import static org.smartdata.hdfs.MultiClusterHarness.TestType.INTER_CLUSTER;
import static org.smartdata.hdfs.MultiClusterHarness.TestType.INTRA_CLUSTER;

/**
 * A MiniCluster for action test.
 */
@RunWith(Parameterized.class)
public abstract class MultiClusterHarness extends MiniClusterHarness {

  public enum TestType {
    INTRA_CLUSTER,
    INTER_CLUSTER
  }

  @Rule
  public TemporaryFolder tmpFolder = new TemporaryFolder();

  @Parameterized.Parameter()
  public TestType testType;

  protected MiniDFSCluster anotherCluster;
  protected DistributedFileSystem anotherDfs;
  protected DFSClient anotherDfsClient;

  @Parameterized.Parameters(name = "Test type - {0}")
  public static Object[] parameters() {
    return new Object[] {INTRA_CLUSTER, INTER_CLUSTER};
  }

  @Before
  public void setUp() throws Exception {
    if (testType == INTRA_CLUSTER) {
      anotherDfs = dfs;
      anotherDfsClient = dfsClient;
      return;
    }
    Configuration clusterConfig = new Configuration(smartContext.getConf());
    clusterConfig.set("hdfs.minidfs.basedir", tmpFolder.newFolder().getAbsolutePath());
    anotherCluster = createCluster(clusterConfig);
    anotherDfs = anotherCluster.getFileSystem();
    anotherDfsClient = anotherDfs.getClient();
  }

  @After
  public void shutdownAnotherCluster() {
    if (anotherCluster != null) {
      anotherCluster.shutdown(true);
    }
  }

  protected Path anotherClusterPath(String parent, String child) {
    return anotherDfs.makeQualified(new Path(parent, child));
  }

  protected String pathToActionArg(Path path) {
    return testType == TestType.INTER_CLUSTER ? path.toString() : path.toUri().getPath();
  }
}
