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

import com.google.common.collect.Sets;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.hdfs.DFSTestUtil;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;
import org.smartdata.hdfs.MultiClusterHarness;

import static org.smartdata.hdfs.action.CopyPreservedAttributesAction.PreserveAttribute.MODIFICATION_TIME;
import static org.smartdata.hdfs.action.CopyPreservedAttributesAction.PreserveAttribute.OWNER;
import static org.smartdata.hdfs.action.CopyPreservedAttributesAction.PreserveAttribute.REPLICATION_NUMBER;

/**
 * Test for CopyFileAction.
 */
public class TestCopyFileAction extends MultiClusterHarness {

  private static final String FILE_TO_COPY_CONTENT = "testContent 112";

  private void copyFile(Path src, Path dest, long length,
      long offset) throws Exception {
    copyFile(src, dest, length, offset, Collections.emptySet());
  }

  private void copyFile(Path src, Path dest, long length,
      long offset, Set<CopyPreservedAttributesAction.PreserveAttribute> preserveAttributes) throws Exception {
    CopyFileAction copyFileAction = new CopyFileAction();
    copyFileAction.setDfsClient(dfsClient);
    copyFileAction.setContext(smartContext);
    Map<String, String> args = new HashMap<>();
    args.put(CopyFileAction.FILE_PATH, src.toUri().getPath());
    args.put(CopyFileAction.DEST_PATH, pathToActionArg(dest));
    args.put(CopyFileAction.LENGTH, "" + length);
    args.put(CopyFileAction.OFFSET_INDEX, "" + offset);

    if (!preserveAttributes.isEmpty()) {
      String attributesOption = preserveAttributes.stream()
          .map(Object::toString)
          .collect(Collectors.joining(","));
      args.put(CopyFileAction.PRESERVE, attributesOption);
    }

    copyFileAction.init(args);
    copyFileAction.run();
    Assert.assertTrue(copyFileAction.getExpectedAfterRun());
  }

  @Test
  public void testFileCopy() throws Exception {
    Path srcPath = new Path("/testCopy/file1");
    Path destPath = anotherClusterPath("/backup", srcPath.getName());

    DFSTestUtil.writeFile(dfs, srcPath, "testCopy1");

    copyFile(srcPath, destPath, 0, 0);

    assertFileContent(destPath, "testCopy1");
  }

  @Test
  public void testCopyWithOffset() throws Exception {
    Path srcPath = new Path("/testCopy/testCopyWithOffset");
    Path destPath = anotherClusterPath("/backup", srcPath.getName());

    byte[] srcFileContent = {0, 1, 2, 3, 4, 5, 6, 7};
    DFSTestUtil.writeFile(dfs, srcPath, srcFileContent);

    copyFile(srcPath, destPath, 4, 4);

    Assert.assertTrue(anotherDfs.exists(destPath));

    byte[] actualDestContent = DFSTestUtil.readFileAsBytes(anotherDfs, destPath);
    byte[] expectedDestContent = Arrays.copyOfRange(srcFileContent, 4, srcFileContent.length);
    Assert.assertArrayEquals(expectedDestContent, actualDestContent);
  }

  @Test
  public void testAppend() throws Exception {
    Path srcPath = new Path("/testCopy/testAppend");
    Path destPath = anotherClusterPath("/backup", srcPath.getName());

    DFSTestUtil.createFile(dfs, srcPath, 100, (short) 3, 0xFEED);
    DFSTestUtil.createFile(anotherDfs, destPath, 50, (short) 3, 0xFEED);

    copyFile(srcPath, destPath, 50, 50);

    Assert.assertTrue(anotherDfs.exists(destPath));
    Assert.assertEquals(100, anotherDfs.getFileStatus(destPath).getLen());
  }

  @Test
  public void testPreserveAllAttributes() throws Exception {
    Path srcPath = createFileWithAttributes("/test/src/fileToCopy");
    Path destPath = anotherClusterPath("/dest", srcPath.getName());

    copyFileWithAttributes(srcPath, destPath,
        Sets.newHashSet(CopyPreservedAttributesAction.PreserveAttribute.values()));

    FileStatus destFileStatus = anotherDfs.getFileStatus(destPath);
    Assert.assertEquals(new FsPermission("777"), destFileStatus.getPermission());
    Assert.assertEquals("newUser", destFileStatus.getOwner());
    Assert.assertEquals("newGroup", destFileStatus.getGroup());
    Assert.assertEquals(2, destFileStatus.getReplication());
    Assert.assertEquals(0L, destFileStatus.getModificationTime());
  }

  @Test
  public void testPreserveSomeAttributes() throws Exception {
    Path srcPath = createFileWithAttributes("/test/src/anotherFileToCopy");
    Path destPath = anotherClusterPath("/dest", srcPath.getName());

    copyFileWithAttributes(srcPath, destPath,
        Sets.newHashSet(OWNER, MODIFICATION_TIME, REPLICATION_NUMBER));

    FileStatus destFileStatus = anotherDfs.getFileStatus(destPath);
    Assert.assertEquals("newUser", destFileStatus.getOwner());
    Assert.assertEquals(0L, destFileStatus.getModificationTime());
    Assert.assertEquals(2, destFileStatus.getReplication());
    Assert.assertNotEquals(new FsPermission("777"), destFileStatus.getPermission());
    Assert.assertNotEquals("newGroup", destFileStatus.getGroup());
  }

  private Path createFileWithAttributes(String path) throws IOException {
    Path srcFilePath = new Path(path);

    DFSTestUtil.writeFile(dfs, srcFilePath, FILE_TO_COPY_CONTENT);

    FsPermission newPermission = new FsPermission("777");
    dfs.setOwner(srcFilePath, "newUser", "newGroup");
    dfs.setPermission(srcFilePath, newPermission);
    dfs.setReplication(srcFilePath, (short) 2);
    dfs.setTimes(srcFilePath, 0L, 1L);

    return srcFilePath;
  }

  private void copyFileWithAttributes(Path srcFilePath, Path destPath,
      Set<CopyPreservedAttributesAction.PreserveAttribute> preserveAttributes) throws Exception {
    copyFile(srcFilePath, destPath, 0, 0, preserveAttributes);
    assertFileContent(destPath, FILE_TO_COPY_CONTENT);
  }

  private void assertFileContent(Path filePath, String expectedContent) throws Exception {
    Assert.assertTrue(anotherDfs.exists(filePath));
    String actualContent = DFSTestUtil.readFile(anotherDfs, filePath);
    Assert.assertEquals(expectedContent, actualContent);
  }
}
