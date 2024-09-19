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
import org.junit.Before;
import org.junit.Test;
import org.smartdata.action.ActionException;
import org.smartdata.hdfs.MiniClusterHarness;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class TestCheckSumAction extends MiniClusterHarness {

  private CheckSumAction action;

  @Before
  public void setUp() {
    action = new CheckSumAction();
    action.setDfsClient(dfsClient);
    action.setContext(smartContext);
  }

  @Test
  public void testCheckSumAction() throws IOException {
    final String file = "/testPath/file1";
    dfsClient.mkdirs("/testPath", null, true);

    // write to HDFS
    byte[] content = ("This is a file containing two blocks" +
        "......................").getBytes(StandardCharsets.UTF_8);
    DFSTestUtil.writeFile(dfs, new Path(file), content);

    Map<String, String> args = new HashMap<>();
    args.put(CheckSumAction.FILE_PATH, file);
    action.init(args);
    action.run();

    List<String> expectedChecksumFiles = Collections.singletonList("/testPath/file1");

    assertTrue(action.getExpectedAfterRun());
    assertEquals(expectedChecksumFiles, getChecksumFiles());
  }

  @Test
  public void testCheckSumActionDirectoryArg() throws IOException {
    final String directoryArg = "/testPath/*";
    dfsClient.mkdirs("/testPath", null, true);

    for (int i = 0; i < 3; ++i) {
      byte[] content = ("Content of file" + i).getBytes(StandardCharsets.UTF_8);
      DFSTestUtil.writeFile(dfs, new Path("/testPath/" + i), content);
    }

    Map<String, String> args = new HashMap<>();
    args.put(CheckSumAction.FILE_PATH, directoryArg);
    action.init(args);
    action.run();

    List<String> expectedChecksumFiles = Arrays.asList(
        "/testPath/0",
        "/testPath/1",
        "/testPath/2"
    );

    assertTrue(action.getExpectedAfterRun());
    assertEquals(expectedChecksumFiles, getChecksumFiles());
  }

  @Test
  public void testThrowIfFileNotFound() throws IOException {
    final String file = "/unknownFile";
    Map<String, String> args = new HashMap<>();
    args.put(CheckSumAction.FILE_PATH, file);
    action.init(args);
    action.run();

    Throwable error = action.getActionStatus().getThrowable();
    assertNotNull(error);
    assertTrue(error instanceof ActionException);
    assertEquals("Provided file doesn't exist: /unknownFile", error.getMessage());
  }

  @Test
  public void testThrowIfDirectoryNotFound() throws IOException {
    final String file = "/unknownDir/*";
    Map<String, String> args = new HashMap<>();
    args.put(CheckSumAction.FILE_PATH, file);
    action.init(args);
    action.run();

    Throwable error = action.getActionStatus().getThrowable();
    assertNotNull(error);
    assertTrue(error instanceof ActionException);
    assertEquals("Provided directory doesn't exist: /unknownDir/", error.getMessage());
  }

  private List<String> getChecksumFiles() throws UnsupportedEncodingException {
    String[] logLines = Optional.ofNullable(action.getActionStatus().getLog())
        .map(log -> log.split("\n"))
        .orElse(new String[0]);

    return Arrays.stream(logLines)
        .map(line -> line.split("\t"))
        .filter(tokens -> tokens.length != 0)
        .map(tokens -> tokens[0])
        .collect(Collectors.toList());
  }
}
