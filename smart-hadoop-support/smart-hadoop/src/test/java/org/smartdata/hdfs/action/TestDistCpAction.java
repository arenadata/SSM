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
import org.apache.hadoop.tools.DistCpOptions;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.smartdata.hdfs.MiniClusterHarness;

import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.apache.hadoop.tools.DistCpOptions.FileAttribute.ACL;
import static org.apache.hadoop.tools.DistCpOptions.FileAttribute.CHECKSUMTYPE;
import static org.apache.hadoop.tools.DistCpOptions.FileAttribute.GROUP;
import static org.apache.hadoop.tools.DistCpOptions.FileAttribute.PERMISSION;
import static org.apache.hadoop.tools.DistCpOptions.FileAttribute.TIMES;
import static org.apache.hadoop.tools.DistCpOptions.FileAttribute.USER;
import static org.smartdata.model.CmdletDescriptor.RULE_ID;

/**
 * Test for DistCpAction.
 */
public class TestDistCpAction extends MiniClusterHarness {

  @Rule
  public TemporaryFolder tmpFolder = new TemporaryFolder();

  public DistCpAction createAction(Map<String, String> args) {
    DistCpAction distCpAction = new DistCpAction();
    distCpAction.setLocalFileSystem(dfs);
    distCpAction.setContext(smartContext);
    distCpAction.init(args);
    return distCpAction;
  }

  @Test
  public void testParseSingleSource() {
    Map<String, String> args = new HashMap<>();
    args.put(DistCpAction.FILE_PATH, "/test/source/dir1");
    args.put(DistCpAction.TARGET_ARG, "hdfs://nn2/test/target/dir1");
    DistCpAction action = createAction(args);
    DistCpOptions distCpOptions = action.buildDistCpOptions();

    Path expectedSource = new Path("/test/source/dir1");
    Assert.assertEquals(Collections.singletonList(expectedSource),
        distCpOptions.getSourcePaths());
    Assert.assertEquals(new Path("hdfs://nn2/test/target/dir1"),
        distCpOptions.getTargetPath());
    Assert.assertEquals(EnumSet.of(USER, GROUP, PERMISSION),
        distCpOptions.getPreserveAttributes());
  }

  @Test
  public void testParseSeveralSources() {
    Map<String, String> args = new HashMap<>();
    args.put(DistCpAction.FILE_PATH, "/test/source/dir1,/test/source/dir2,/test/source/dir3");
    args.put(DistCpAction.TARGET_ARG, "hdfs://nn2/test/target/dir1");
    DistCpAction action = createAction(args);
    DistCpOptions distCpOptions = action.buildDistCpOptions();

    List<Path> expectedSources = Stream.of(
            "/test/source/dir1", "/test/source/dir2", "/test/source/dir3")
        .map(Path::new)
        .collect(Collectors.toList());
    Assert.assertEquals(expectedSources,
        distCpOptions.getSourcePaths());
    Assert.assertEquals(new Path("hdfs://nn2/test/target/dir1"),
        distCpOptions.getTargetPath());
  }

  @Test
  public void testParseSourceFileListingOption() {
    final String sourcesPath = "/test/sources.txt";

    Map<String, String> args = new HashMap<>();
    args.put(DistCpAction.SOURCE_PATH_LIST_FILE, sourcesPath);
    args.put(DistCpAction.TARGET_ARG, "hdfs://nn2/test/target/dir1");
    DistCpAction action = createAction(args);
    DistCpOptions distCpOptions = action.buildDistCpOptions();

    Assert.assertEquals(new Path(sourcesPath),
        distCpOptions.getSourceFileListing());
    Assert.assertEquals(new Path("hdfs://nn2/test/target/dir1"),
        distCpOptions.getTargetPath());
  }

  @Test
  public void testThrowIfNoSourceOptionProvided() {
    Map<String, String> args = new HashMap<>();
    args.put(DistCpAction.TARGET_ARG, "hdfs://nn2/test/target/dir1");

    IllegalArgumentException exception = Assert.assertThrows(
        IllegalArgumentException.class, () -> createAction(args).buildDistCpOptions());
    Assert.assertEquals("Source paths not provided, please provide either -file either -f argument",
        exception.getMessage());
  }

  @Test
  public void testThrowIfEmptySourceOptionProvided() {
    Map<String, String> args = new HashMap<>();
    args.put(DistCpAction.FILE_PATH, "");
    args.put(DistCpAction.TARGET_ARG, "hdfs://nn2/test/target/dir1");

    IllegalArgumentException exception = Assert.assertThrows(
        IllegalArgumentException.class, () -> createAction(args).buildDistCpOptions());
    Assert.assertEquals("Source paths not provided, please provide either -file either -f argument",
        exception.getMessage());
  }

  @Test
  public void testThrowIfBothSourceOptionsProvided() {
    Map<String, String> args = new HashMap<>();
    args.put(DistCpAction.FILE_PATH, "test_path");
    args.put(DistCpAction.SOURCE_PATH_LIST_FILE, "test_path_listing");
    args.put(DistCpAction.TARGET_ARG, "hdfs://nn2/test/target/dir1");

    IllegalArgumentException exception = Assert.assertThrows(
        IllegalArgumentException.class, () -> createAction(args).buildDistCpOptions());
    Assert.assertEquals(
        "-file and -f can't be used at the same time. Use only one of the options for specifying source paths.",
        exception.getMessage());
  }

  @Test
  public void testThrowIfTargetOptionNotProvided() {
    Map<String, String> args = new HashMap<>();
    args.put(DistCpAction.SOURCE_PATH_LIST_FILE, "test_path_listing");

    IllegalArgumentException exception = Assert.assertThrows(
        IllegalArgumentException.class, () -> createAction(args).buildDistCpOptions());
    Assert.assertEquals("Required argument not present: -target", exception.getMessage());
  }

  @Test
  public void testThrowIfEmptyTargetOptionProvided() {
    Map<String, String> args = new HashMap<>();
    args.put(DistCpAction.SOURCE_PATH_LIST_FILE, "test_path_listing");
    args.put(DistCpAction.TARGET_ARG, "");

    IllegalArgumentException exception = Assert.assertThrows(
        IllegalArgumentException.class, () -> createAction(args).buildDistCpOptions());
    Assert.assertEquals("Required argument not present: -target", exception.getMessage());
  }

  @Test
  public void testParseDistCpOptionalArgs() {
    Map<String, String> args = new HashMap<>();
    args.put(DistCpAction.FILE_PATH, "/test/source/dir1");
    args.put(DistCpAction.TARGET_ARG, "hdfs://nn2/test/target/dir1");
    args.put(RULE_ID, "183");
    args.put("-pcat", "");
    args.put("-m", "16");
    args.put("-strategy", "dynamic");
    args.put("-update", "");
    DistCpAction action = createAction(args);
    DistCpOptions distCpOptions = action.buildDistCpOptions();

    Path expectedSource = new Path("/test/source/dir1");

    Assert.assertEquals(Collections.singletonList(expectedSource),
        distCpOptions.getSourcePaths());
    Assert.assertEquals(new Path("hdfs://nn2/test/target/dir1"),
        distCpOptions.getTargetPath());
    Assert.assertEquals(16, distCpOptions.getMaxMaps());
    Assert.assertEquals("dynamic", distCpOptions.getCopyStrategy());
    Assert.assertTrue(distCpOptions.shouldSyncFolder());
    Assert.assertEquals(EnumSet.of(CHECKSUMTYPE, ACL, TIMES),
        distCpOptions.getPreserveAttributes());
  }
}
