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

import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.DFSTestUtil;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runners.Parameterized;
import org.smartdata.hdfs.MiniClusterHarness;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Test for MergeFileAction
 */
public class TestMergeFileAction extends MiniClusterHarness {

  @Parameterized.Parameter
  public boolean useAbsolutePath;

  @Parameterized.Parameters(name = "useAbsolutePath = {0}")
  public static Object[] parameters() {
    return new Object[]{true, false};
  }

  @Test
  public void testFileMerge() throws IOException {
    String srcPath = "/testConcat";
    Path file1 = new Path(srcPath, "file1");
    Path file2 = new Path(srcPath, "file2");
    String target = "/target";

    if (useAbsolutePath) {
      file1 = dfs.makeQualified(file1);
      file2 = dfs.makeQualified(file2);
    }

    dfs.mkdirs(new Path(srcPath));
    DFSTestUtil.writeFile(dfs, new Path(target), "");
    //write to DISK
    //write 50 Bytes to file1 and 50 Byte to file2. then concat them
    createFileWithContent(file1, (byte) 1);
    createFileWithContent(file2, (byte) 2);

    MergeFileAction mergeFileAction = new MergeFileAction();
    mergeFileAction.setLocalFileSystem(dfs);
    mergeFileAction.setContext(smartContext);
    Map<String, String> args = new HashMap<>();
    args.put(MergeFileAction.FILE_PATH, file1 + "," + file2);
    args.put(MergeFileAction.DEST_PATH, dfs.getUri() + target);
    mergeFileAction.init(args);
    mergeFileAction.run();

    Assert.assertTrue(mergeFileAction.getExpectedAfterRun());
    Assert.assertTrue(dfsClient.exists(target));
    //read and check file
    FSDataInputStream in = dfs.open(new Path(target), 50);
    for (int i = 0; i < DEFAULT_BLOCK_SIZE; i++) {
      Assert.assertEquals(1, in.readByte());
    }
    for (int i = 0; i < DEFAULT_BLOCK_SIZE; i++) {
      Assert.assertEquals(2, in.readByte());
    }
  }

  private void createFileWithContent(Path path, byte content) throws IOException {
    byte[] contentBytes = new byte[DEFAULT_BLOCK_SIZE];
    Arrays.fill(contentBytes, content);
    DFSTestUtil.writeFile(dfs, path, contentBytes);
  }
}
