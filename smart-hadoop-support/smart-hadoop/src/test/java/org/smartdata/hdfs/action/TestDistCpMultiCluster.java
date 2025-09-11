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
package org.smartdata.hdfs.action;

import com.google.common.collect.ImmutableMap;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.DFSTestUtil;
import org.junit.Assert;
import org.junit.Test;
import org.smartdata.hdfs.MultiClusterHarness;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.smartdata.model.CmdletDescriptor.RULE_ID;

/**
 * Test for DistCpAction.
 */
public class TestDistCpMultiCluster extends MultiClusterHarness {
  @Test
  public void testCopyToTargetCluster() throws Exception {
    testCopyToCluster(dfs, anotherDfs);
  }

  @Test
  public void testCopyFromTargetCluster() throws Exception {
    testCopyToCluster(anotherDfs, dfs);
  }

  @Test
  public void testCopyToTargetClusterAsRuleAction() throws Exception {
    testCopyToCluster(dfs, anotherDfs, ImmutableMap.of(RULE_ID, "123"));
  }

  private void testCopyToCluster(FileSystem sourceFs, FileSystem targetFs) throws Exception {
    testCopyToCluster(sourceFs, targetFs, new HashMap<>());
  }

  private void testCopyToCluster(
      FileSystem sourceFs, FileSystem targetFs, Map<String, String> additionalArgs) throws Exception {
    Map<String, String> args = new HashMap<>();
    String sourcePath = sourceFs.getUri() + "/test/source/dir1";
    String targetPath = targetFs.getUri() + "/test/target/";

    args.put(DistCpAction.FILE_PATH, sourcePath);
    args.put(DistCpAction.TARGET_ARG, targetPath);
    args.putAll(additionalArgs);
    DistCpAction action = createAction(args);

    writeToFile(sourceFs, new Path(sourcePath + "/testFile1"), "data-1");
    writeToFile(sourceFs, new Path(sourcePath + "/testFile2"), "another file data");
    writeToFile(sourceFs, new Path(sourcePath + "/inner/testFile3"), "inner data");

    action.execute();

    assertFileContent(targetFs, new Path(targetPath + "/dir1/testFile1"), "data-1");
    assertFileContent(targetFs, new Path(targetPath + "/dir1/testFile2"), "another file data");
    assertFileContent(targetFs, new Path(targetPath + "/dir1/inner/testFile3"), "inner data");
  }

  private DistCpAction createAction(Map<String, String> args) {
    DistCpAction distCpAction = new DistCpAction();
    distCpAction.setLocalFileSystem(dfs);
    distCpAction.setContext(smartContext);
    distCpAction.init(args);
    return distCpAction;
  }

  private void assertFileContent(
      final FileSystem fileSystem, final Path path, final String expectedData) throws IOException {
    Assert.assertTrue(fileSystem.exists(path));
    Assert.assertEquals(expectedData, new String(
        DFSTestUtil.readFileAsBytes(fileSystem, path),
        StandardCharsets.UTF_8));
  }

  private void writeToFile(
      final FileSystem fileSystem, final Path path, final String data) throws IOException {
    fileSystem.mkdirs(path.getParent());
    DFSTestUtil.writeFile(fileSystem, path, data);
  }
}
