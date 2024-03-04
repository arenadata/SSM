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

import java.io.UnsupportedEncodingException;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.DFSTestUtil;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.smartdata.hdfs.MiniClusterHarness;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Test for MetaDataAction
 */
@RunWith(Parameterized.class)
public class TestMetaDataAction extends MiniClusterHarness {

  @Parameterized.Parameter()
  public boolean isRemoteCopy;

  @Parameterized.Parameters(name = "Remote copy - {0}")
  public static Object[] parameters() {
    return new Object[] {true, false};
  }

  @Test
  public void testMetadataChange() throws IOException {
    Map<String, String> args = new HashMap<>();
    args.put(MetaDataAction.OWNER_NAME, "user");
    args.put(MetaDataAction.GROUP_NAME, "group");
    args.put(MetaDataAction.BLOCK_REPLICATION, "7");
    args.put(MetaDataAction.PERMISSION, "511");
    args.put(MetaDataAction.MTIME, "10");

    FileStatus fileStatus = updateMetadata(args);
    Assert.assertEquals("user", fileStatus.getOwner());
    Assert.assertEquals("group", fileStatus.getGroup());
    Assert.assertEquals(7, fileStatus.getReplication());
    Assert.assertEquals("rwxrwxrwx", fileStatus.getPermission().toString());
    Assert.assertEquals(10L, fileStatus.getModificationTime());
  }

  @Test
  public void testPartialMetadataChange() throws IOException {
    Map<String, String> args = new HashMap<>();
    args.put(MetaDataAction.GROUP_NAME, "group");
    args.put(MetaDataAction.BLOCK_REPLICATION, "7");
    args.put(MetaDataAction.MTIME, "10");

    FileStatus fileStatus = updateMetadata(args);
    Assert.assertEquals("group", fileStatus.getGroup());
    Assert.assertEquals(7, fileStatus.getReplication());
    Assert.assertEquals(10L, fileStatus.getModificationTime());
  }

  private FileStatus updateMetadata(Map<String, String> args) throws IOException {
    Path srcPath = new Path("/test/file");
    DFSTestUtil.writeFile(dfs, srcPath, "data");

    args.put(MetaDataAction.FILE_PATH, pathToActionArg(srcPath));
    runAction(args);

    return dfs.getFileStatus(srcPath);
  }

  private void runAction(Map<String, String> args) throws UnsupportedEncodingException {
    MetaDataAction metaFileAction = new MetaDataAction();
    metaFileAction.setDfsClient(dfsClient);
    metaFileAction.setContext(smartContext);

    metaFileAction.init(args);
    metaFileAction.run();

    Assert.assertTrue(metaFileAction.getExpectedAfterRun());
  }

  protected String pathToActionArg(Path path) {
    return isRemoteCopy ? path.toString() : path.toUri().getPath();
  }
}
