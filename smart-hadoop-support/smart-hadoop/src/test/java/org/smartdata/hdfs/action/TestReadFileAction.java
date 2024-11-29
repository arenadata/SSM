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

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.DFSTestUtil;
import org.junit.Assert;
import org.junit.Test;
import org.smartdata.hdfs.MiniClusterHarness;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class TestReadFileAction extends MiniClusterHarness {
  protected void writeFile(String filePath, int length) throws IOException {
    DFSTestUtil.createFile(dfs, new Path(filePath), length, (short) 1, 0L);
  }

  @Test
  public void testInit() {
    ReadFileAction readFileAction = new ReadFileAction();
    Map<String, String> args = new HashMap<>();
    args.put(ReadFileAction.FILE_PATH, "Test");
    readFileAction.init(args);
    args.put(ReadFileAction.BUF_SIZE, "4096");
    readFileAction.init(args);
  }

  @Test
  public void testExecute() throws IOException {
    String filePath = "/testWriteFile/file";
    int size = 66560;
    writeFile(filePath, size);
    ReadFileAction readFileAction = new ReadFileAction();
    readFileAction.setLocalFileSystem(dfs);
    readFileAction.setContext(smartContext);
    Map<String, String> args = new HashMap<>();
    args.put(ReadFileAction.FILE_PATH, filePath);
    readFileAction.init(args);
    readFileAction.run();
    Assert.assertTrue(readFileAction.getExpectedAfterRun());
  }
}
