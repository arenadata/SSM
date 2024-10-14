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
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.smartdata.hdfs.MiniClusterHarness;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Test for ListFileAction.
 */
@RunWith(Parameterized.class)
public class TestListFileAction extends MiniClusterHarness {

  private ListFileAction listFileAction;
  private TimeZone timeZoneToRestore;

  @Parameter
  public boolean useFullRootPath;

  @Parameters(name = "useFullRootPath = {0}")
  public static Object[] parameters() {
    return new Object[]{true, false};
  }

  @Before
  public void buildAction() {
    timeZoneToRestore = TimeZone.getDefault();
    TimeZone.setDefault(TimeZone.getTimeZone("UTC"));

    listFileAction = new ListFileAction();
    listFileAction.setDfsClient(dfsClient);
    listFileAction.setContext(smartContext);
  }

  /*
   * test/
   * --- file1
   * --- dir1/
   *     --- file1
   *     --- subdir/
   *         --- file11
   *         --- file12
   *     --- emptydir/
   * --- dir2/
   *     --- file21
   *     --- file22
   */
  @Before
  public void createDirectoryForListing() {
    List<String> paths = new ArrayList<>();

    Stream.of(
            "/test",
            "/test/dir1",
            "/test/dir2",
            "/test/dir1/subdir",
            "/test/dir1/emptydir"
        )
        .peek(paths::add)
        .forEach(this::createDirectory);

    Stream.of(
            "/test/file1",
            "/test/file2",
            "/test/dir1/file1",
            "/test/dir1/subdir/file11",
            "/test/dir1/subdir/file12",
            "/test/dir2/file21",
            "/test/dir2/file22"
        )
        .peek(paths::add)
        .forEach(this::createFile);

    paths.forEach(this::setFileAttributes);
  }

  @After
  public void restoreTimezone() {
    TimeZone.setDefault(timeZoneToRestore);
  }

  @Test
  public void testListFiles() {
    String result = runAction("/test");

    String expectedListing = "drwxr-xr-x     0 test	test	            0 1970-01-01 00:00 "
        + cluster.getURI() + "/test/dir1\n"
        + "drwxr-xr-x     0 test\ttest\t            0 1970-01-01 00:00 "
        + cluster.getURI() + "/test/dir2\n"
        + "-rw-r--r--     3 test\ttest\t         2048 1970-01-01 00:00 "
        + cluster.getURI() + "/test/file1\n"
        + "-rw-r--r--     3 test\ttest\t         2048 1970-01-01 00:00 "
        + cluster.getURI() + "/test/file2\n";

    assertTrue(listFileAction.getExpectedAfterRun());
    assertEquals(expectedListing, result);
  }

  @Test
  public void testListFilesRecursively() {
    String result = runAction("/test/dir1", ListFileAction.RECURSIVELY);

    String expectedListing = "drwxr-xr-x     0 test	test	            0 1970-01-01 00:00 "
        + cluster.getURI() + "/test/dir1/emptydir\n"
        + "-rw-r--r--     3 test\ttest\t         2048 1970-01-01 00:00 "
        + cluster.getURI() + "/test/dir1/file1\n"
        + "drwxr-xr-x     0 test\ttest\t            0 1970-01-01 00:00 "
        + cluster.getURI() + "/test/dir1/subdir\n"
        + "-rw-r--r--     3 test\ttest\t         2048 1970-01-01 00:00 "
        + cluster.getURI() + "/test/dir1/subdir/file11\n"
        + "-rw-r--r--     3 test\ttest\t         2048 1970-01-01 00:00 "
        + cluster.getURI() + "/test/dir1/subdir/file12\n";

    assertTrue(listFileAction.getExpectedAfterRun());
    assertEquals(expectedListing, result);
  }

  @Test
  public void testListFilesWithPrettySizes() {
    String result = runAction("/test/dir1",
        ListFileAction.RECURSIVELY, ListFileAction.PRETTY_SIZES);

    String expectedListing = "drwxr-xr-x     0 test	test	            0 1970-01-01 00:00 "
        + cluster.getURI() + "/test/dir1/emptydir\n"
        + "-rw-r--r--     3 test\ttest\t          2 K 1970-01-01 00:00 "
        + cluster.getURI() + "/test/dir1/file1\n"
        + "drwxr-xr-x     0 test\ttest\t            0 1970-01-01 00:00 "
        + cluster.getURI() + "/test/dir1/subdir\n"
        + "-rw-r--r--     3 test\ttest\t          2 K 1970-01-01 00:00 "
        + cluster.getURI() + "/test/dir1/subdir/file11\n"
        + "-rw-r--r--     3 test\ttest\t          2 K 1970-01-01 00:00 "
        + cluster.getURI() + "/test/dir1/subdir/file12\n";

    assertTrue(listFileAction.getExpectedAfterRun());
    assertEquals(expectedListing, result);
  }

  @Test
  public void testListSimpleFile() {
    String result = runAction("/test/file1", ListFileAction.RECURSIVELY);

    String expectedListing = "-rw-r--r--     3 test\ttest\t         2048 1970-01-01 00:00 "
        + cluster.getURI() + "/test/file1\n";

    assertTrue(listFileAction.getExpectedAfterRun());
    assertEquals(expectedListing, result);
  }

  private String runAction(String root, String... arguments) {
    Map<String, String> args = new HashMap<>();
    args.put(
        ListFileAction.FILE_PATH,
        useFullRootPath
            ? cluster.getURI() + "/" + root
            : root);

    for (String arg : arguments) {
      args.put(arg, "");
    }

    listFileAction.init(args);
    listFileAction.run();

    return listFileAction.getActionStatus().getResult();
  }

  private void createDirectory(String directory) {
    try {
      Path path = new Path(directory);
      dfs.mkdirs(path);
    } catch (IOException e) {
      Assert.fail(e.getMessage());
    }
  }

  private void createFile(String file) {
    try {
      Path path = new Path(file);
      DFSTestUtil.writeFile(dfs, path, new byte[2048]);
    } catch (IOException e) {
      Assert.fail(e.getMessage());
    }
  }

  private void setFileAttributes(String file) {
    try {
      Path path = new Path(file);
      dfs.setOwner(path, "test", "test");
      dfs.setTimes(path, 0, 0);
    } catch (IOException e) {
      Assert.fail(e.getMessage());
    }
  }
}
