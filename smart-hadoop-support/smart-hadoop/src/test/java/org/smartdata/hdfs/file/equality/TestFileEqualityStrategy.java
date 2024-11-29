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
package org.smartdata.hdfs.file.equality;

import java.io.IOException;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.DFSTestUtil;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.smartdata.hdfs.MultiClusterHarness;
import org.smartdata.model.FileInfo;

import static org.smartdata.hdfs.MultiClusterHarness.TestType.INTER_CLUSTER;
import static org.smartdata.hdfs.MultiClusterHarness.TestType.INTRA_CLUSTER;
import static org.smartdata.hdfs.file.equality.FileEqualityStrategy.Strategy.CHECKSUM;
import static org.smartdata.hdfs.file.equality.FileEqualityStrategy.Strategy.FILE_LENGTH;

@RunWith(Parameterized.class)
public class TestFileEqualityStrategy extends MultiClusterHarness {

  private FileEqualityStrategy fileEqualityStrategy;

  @Parameter(1)
  public FileEqualityStrategy.Strategy strategy;

  @Before
  public void initStrategy() {
    fileEqualityStrategy = FileEqualityStrategy.of(
        strategy, smartContext.getConf());
  }

  @Parameters(name = "Test type - {0}, Strategy - {1}")
  public static Object[] parameters() {
    return new Object[][] {
        {INTRA_CLUSTER, FILE_LENGTH},
        {INTRA_CLUSTER, CHECKSUM},
        {INTER_CLUSTER, CHECKSUM}
    };
  }

  @Test
  public void testCompareFilesWithDifferentLength() throws IOException {
    Path srcPath = new Path("/src");
    Path destPath = anotherClusterPath("/", "dest");

    DFSTestUtil.writeFile(dfs, srcPath, "data");
    DFSTestUtil.writeFile(anotherDfs, destPath, "data, but a little bit longer");

    boolean areFilesEqual = checkFilesEquality(srcPath, destPath);
    Assert.assertFalse(areFilesEqual);
  }

  @Test
  public void testCompareEqualFiles() throws IOException {
    Path srcPath = new Path("/src");
    Path destPath = anotherClusterPath("/", "dest");

    DFSTestUtil.writeFile(dfs, srcPath, "another data");
    DFSTestUtil.writeFile(anotherDfs, destPath, "another data");

    boolean areFilesEqual = checkFilesEquality(srcPath, destPath);
    Assert.assertTrue(areFilesEqual);
  }

  @Test
  public void testCompareFileWithItself() throws IOException {
    Assume.assumeTrue(testType == INTRA_CLUSTER);

    Path srcPath = new Path("/src");
    DFSTestUtil.writeFile(dfs, srcPath, "data");

    boolean areFilesEqual = checkFilesEquality(srcPath, anotherClusterPath(srcPath));
    Assert.assertTrue(areFilesEqual);
  }

  @Test
  public void testCompareNotEqualFilesWithEqualLength() throws IOException {
    Assume.assumeTrue(strategy == CHECKSUM);

    Path srcPath = new Path("/src");
    Path destPath = anotherClusterPath("/", "dest");

    DFSTestUtil.writeFile(dfs, srcPath, "12345678");
    DFSTestUtil.writeFile(anotherDfs, destPath, "87654321");

    boolean areFilesEqual = checkFilesEquality(srcPath, destPath);
    Assert.assertFalse(areFilesEqual);
  }

  private boolean checkFilesEquality(Path srcPath, Path destPath) throws IOException {
    FileStatus srcFileStatus = dfs.getFileStatus(srcPath);
    FileInfo srcFileInfo = FileInfo.builder()
        .setPath(srcPath.toUri().getPath())
        .setLength(srcFileStatus.getLen())
        .build();
    FileStatus destFileStatus = anotherDfs.getFileStatus(destPath);

    return fileEqualityStrategy.areEqual(srcFileInfo, destFileStatus);
  }
}
