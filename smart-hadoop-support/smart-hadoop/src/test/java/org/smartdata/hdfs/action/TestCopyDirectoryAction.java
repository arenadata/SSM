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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.hdfs.MultiClusterHarness;
import org.smartdata.protocol.message.ActionStatus;

/**
 * Test for CopyDirectoryAction.
 */
public class TestCopyDirectoryAction extends MultiClusterHarness {

  private CopyDirectoryAction copyDirectoryAction;

  @Before
  public void setupAction() {
    copyDirectoryAction = new CopyDirectoryAction();
    copyDirectoryAction.setDfsClient(dfsClient);
    copyDirectoryAction.setContext(smartContext);
  }

  private void copyDirectory(Path src, Path dest,
      Set<CopyPreservedAttributesAction.PreserveAttribute> preserveAttributes) throws Exception {
    Map<String, String> args = new HashMap<>();
    args.put(CopyDirectoryAction.FILE_PATH, src.toUri().getPath());
    args.put(CopyDirectoryAction.DEST_PATH, pathToActionArg(dest));

    if (!preserveAttributes.isEmpty()) {
      String attributesOption = preserveAttributes.stream()
          .map(Object::toString)
          .collect(Collectors.joining(","));
      args.put(CopyFileAction.PRESERVE, attributesOption);
    }

    copyDirectoryAction.init(args);
    copyDirectoryAction.run();

    ActionStatus actionStatus = copyDirectoryAction.getActionStatus();
    Assert.assertTrue(actionStatus.isFinished());
    Assert.assertNull(actionStatus.getThrowable());
  }

  @Test
  public void testDirectoryCopy() throws Exception {
    Path srcPath = new Path("/test/src");
    Path destPath = anotherClusterPath("/dest", srcPath.getName());

    dfs.mkdirs(srcPath);

    copyDirectory(srcPath, destPath, Collections.emptySet());
    Assert.assertTrue(anotherDfs.exists(destPath));
  }

  @Test
  public void testPreserveAllAttributes() throws Exception {
    Path srcPath = new Path("/test/src");
    Path destPath = anotherClusterPath("/dest", srcPath.getName());

    dfs.mkdirs(srcPath);
    dfs.setOwner(srcPath, "testUser", "testGroup");
    dfs.setPermission(srcPath, new FsPermission("777"));

    copyDirectory(srcPath, destPath, Collections.emptySet());

    FileStatus destFileStatus = anotherDfs.getFileStatus(destPath);
    Assert.assertTrue(anotherDfs.exists(destPath));
    Assert.assertEquals(new FsPermission("777"), destFileStatus.getPermission());
    Assert.assertEquals("testUser", destFileStatus.getOwner());
    Assert.assertEquals("testGroup", destFileStatus.getGroup());
  }

  @Test
  public void testPreserveSomeAttributes() throws Exception {
    Path srcPath = new Path("/test/src");
    Path destPath = anotherClusterPath("/dest", srcPath.getName());

    dfs.mkdirs(srcPath);
    dfs.setOwner(srcPath, "testUser", dfs.getFileStatus(srcPath).getGroup());

    copyDirectory(srcPath, destPath, Collections.emptySet());

    FileStatus destFileStatus = anotherDfs.getFileStatus(destPath);
    Assert.assertTrue(anotherDfs.exists(destPath));
    Assert.assertEquals("testUser", destFileStatus.getOwner());
    Assert.assertNotEquals("testGroup", destFileStatus.getGroup());
  }

  @Test
  public void testThrowIfSrcDirNotExist() {
    Path srcPath = new Path("/test/non_existed");
    Path destPath = anotherClusterPath("/dest", srcPath.getName());
    Assert.assertThrows(
        AssertionError.class,
        () -> copyDirectory(srcPath, destPath, Collections.emptySet()));
  }
}
