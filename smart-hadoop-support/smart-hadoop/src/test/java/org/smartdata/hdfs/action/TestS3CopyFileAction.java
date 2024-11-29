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
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.s3a.S3AFileSystem;
import org.apache.hadoop.hdfs.DFSTestUtil;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.smartdata.hdfs.MiniClusterHarness;
import org.smartdata.hdfs.SmartMinIOContainer;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Test for CopyFileAction.
 */
public class TestS3CopyFileAction extends MiniClusterHarness {

  private static final String FILE_TO_COPY_CONTENT = "1234567890";
  private static final String FILE_TO_APPEND_CONTENT = "qwertyuiop";

  private static final String MINIO_USER = "minioAdmin";
  private static final String MINIO_PASSWORD = "minioPassword";
  private static final String TEST_BUCKET = "bucket";

  private FileSystem s3FileSystem;

  @Rule
  public SmartMinIOContainer minIOContainer =
      new SmartMinIOContainer("minio/minio:RELEASE.2024-08-17T01-24-54Z")
          .withBuckets(TEST_BUCKET)
          .withUserName(MINIO_USER)
          .withPassword(MINIO_PASSWORD);

  @Before
  public void initDestFs() throws Exception {
    s3FileSystem = FileSystem.get(
        URI.create("s3a://" + TEST_BUCKET),
        smartContext.getConf());
  }

  @After
  public void closeDestFs() throws Exception {
    if (s3FileSystem != null) {
      s3FileSystem.close();
    }
  }

  @Override
  protected void initConf(Configuration conf) {
    super.initConf(conf);
    conf.set("fs.s3a.impl", S3AFileSystem.class.getName());
    conf.set("fs.s3a.endpoint", minIOContainer.getS3URL());
    conf.set("fs.s3a.access.key", MINIO_USER);
    conf.set("fs.s3a.secret.key", MINIO_PASSWORD);
    conf.setBoolean("fs.s3a.path.style.access", true);
    conf.setBoolean("fs.s3a.connection.ssl.enabled", false);
  }

  @Test
  public void testCreateFile() throws Exception {
    Path srcPath = new Path("/testCopy/file1");
    Path destPath = new Path("s3a://bucket/file2");

    DFSTestUtil.writeFile(dfs, srcPath, FILE_TO_COPY_CONTENT);

    copyFile(srcPath, destPath, 0, 0);

    assertFileContent(destPath, FILE_TO_COPY_CONTENT);
  }

  @Test
  public void testAppendFile() throws Exception {
    Path srcPath = new Path("/testCopy/testAppend");
    Path destPath = new Path("s3a://bucket/fileAppended");

    DFSTestUtil.writeFile(dfs, srcPath, FILE_TO_COPY_CONTENT + FILE_TO_APPEND_CONTENT);
    DFSTestUtil.writeFile(s3FileSystem, destPath, FILE_TO_COPY_CONTENT);

    copyFile(srcPath, destPath,
        FILE_TO_APPEND_CONTENT.getBytes().length,
        FILE_TO_COPY_CONTENT.getBytes().length);

    assertFileContent(destPath, FILE_TO_COPY_CONTENT + FILE_TO_APPEND_CONTENT);
  }

  private void copyFile(Path src, Path dest, long length, long offset,
      CopyPreservedAttributesAction.PreserveAttribute... preserveAttributes) {
    CopyFileAction copyFileAction = new CopyFileAction();
    copyFileAction.setLocalFileSystem(dfs);
    copyFileAction.setContext(smartContext);

    Map<String, String> args = new HashMap<>();
    args.put(CopyFileAction.FILE_PATH, src.toUri().getPath());
    args.put(CopyFileAction.DEST_PATH, dest.toString());
    args.put(CopyFileAction.LENGTH, String.valueOf(length));
    args.put(CopyFileAction.OFFSET_INDEX, String.valueOf(offset));
    args.put(CopyFileAction.FORCE, "");

    if (preserveAttributes.length != 0) {
      String attributesOption = Sets.newHashSet(preserveAttributes)
          .stream()
          .map(Object::toString)
          .collect(Collectors.joining(","));
      args.put(CopyFileAction.PRESERVE, attributesOption);
    }

    copyFileAction.init(args);
    copyFileAction.run();

    if (!copyFileAction.getExpectedAfterRun()) {
      throw new RuntimeException("Action failed", copyFileAction.getThrowable());
    }
  }

  private void assertFileContent(Path filePath, String expectedContent) throws Exception {
    Assert.assertTrue(s3FileSystem.exists(filePath));
    String actualContent = DFSTestUtil.readFile(s3FileSystem, filePath);
    Assert.assertEquals(expectedContent, actualContent);
  }
}
