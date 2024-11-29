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
package org.smartdata.server;

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.DFSTestUtil;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.junit.Assert;
import org.junit.Test;
import org.smartdata.exception.ActionRejectedException;
import org.smartdata.metastore.MetaStore;
import org.smartdata.model.ActionInfo;
import org.smartdata.model.FileInfo;
import org.smartdata.model.RuleState;
import org.smartdata.model.S3FileState;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class TestCopy2S3Scheduler extends MiniSmartClusterHarness {

  @Test
  public void testThrowIfNoArgsProvided() throws Exception {
    waitTillSSMExitSafeMode();

    ActionRejectedException exception = assertThrows(
        ActionRejectedException.class,
        () -> ssm.getCmdletManager().submitCmdlet("copy2s3"));

    assertEquals("Required argument not found: -file", exception.getMessage());
  }

  @Test
  public void testThrowIfNoFileArgProvided() throws Exception {
    waitTillSSMExitSafeMode();

    ActionRejectedException exception = assertThrows(
        ActionRejectedException.class,
        () -> ssm.getCmdletManager().submitCmdlet("copy2s3 -key val"));

    assertEquals("Required argument not found: -file", exception.getMessage());
  }

  @Test
  public void testThrowIfSrcFileNotFound() throws Exception {
    waitTillSSMExitSafeMode();

    ActionRejectedException exception = assertThrows(
        ActionRejectedException.class,
        () -> ssm.getCmdletManager().submitCmdlet("copy2s3 -file /test.bin"));

    assertEquals("The source file /test.bin not found", exception.getMessage());
  }

  @Test
  public void testThrowIfSrcFileIsEmpty() throws Exception {
    waitTillSSMExitSafeMode();

    ssm.getMetaStore().insertFile(FileInfo.builder()
        .setPath("/empty.file")
        .setLength(0L)
        .build(), true);

    ActionRejectedException exception = assertThrows(
        ActionRejectedException.class,
        () -> ssm.getCmdletManager().submitCmdlet("copy2s3 -file /empty.file"));

    assertEquals("The source file /empty.file length is 0", exception.getMessage());
  }

  @Test
  public void testThrowIfSrcFileIsAlreadyCopied() throws Exception {
    waitTillSSMExitSafeMode();

    ssm.getMetaStore().insertFile(FileInfo.builder()
        .setPath("/test.file")
        .setLength(10L)
        .build(), true);

    ssm.getMetaStore().insertUpdateFileState(new S3FileState("/test.file"));

    ActionRejectedException exception = assertThrows(
        ActionRejectedException.class,
        () -> ssm.getCmdletManager().submitCmdlet("copy2s3 -file /test.file"));

    assertEquals("The source file /test.file is already copied", exception.getMessage());
  }

  @Test
  public void testThrowIfSrcFileIsLocked() throws Exception {
    waitTillSSMExitSafeMode();

    ssm.getMetaStore().insertFile(FileInfo.builder()
        .setPath("/test.file")
        .setLength(10L)
        .build(), true);

    ssm.getCmdletManager()
        .submitCmdlet("sleep -ms 10000; copy2s3 -file /test.file");

    ActionRejectedException exception = assertThrows(
        ActionRejectedException.class,
        () -> ssm.getCmdletManager().submitCmdlet("copy2s3 -file /test.file"));

    assertEquals("The source file /test.file is locked", exception.getMessage());
  }

  @Test(timeout = 45000)
  public void testDir() throws Exception {
    waitTillSSMExitSafeMode();
    MetaStore metaStore = ssm.getMetaStore();

    DistributedFileSystem dfs = cluster.getFileSystem();
    final String srcPath = "/src/";
    dfs.mkdirs(new Path(srcPath));
    // Write to src
    for (int i = 0; i < 3; i++) {
      // Create test files
      DFSTestUtil.createFile(dfs, new Path(srcPath + i),
          1024, (short) 1, 1);
    }
    long ruleId = ssm.getRuleManager().submitRule(
        "file: path matches \"/src/*\"| copy2s3 -dest s3a://xxxctest/dest/",
        RuleState.ACTIVE);
    List<ActionInfo> actions;
    do {
      actions = metaStore.getActionsByRuleId(ruleId);
      Thread.sleep(1000);
    } while (actions.size() < 3);
  }

  @Test(timeout = 45000)
  public void testZeroLength() throws Exception {
    waitTillSSMExitSafeMode();
    MetaStore metaStore = ssm.getMetaStore();
    DistributedFileSystem dfs = cluster.getFileSystem();
    final String srcPath = "/src/";
    dfs.mkdirs(new Path(srcPath));
    // Write to src
    for (int i = 0; i < 3; i++) {
      // Create test files
      DFSTestUtil.createFile(dfs, new Path(srcPath + i),
          0, (short) 1, 1);
    }
    long ruleId = ssm.getRuleManager().submitRule(
        "file: path matches \"/src/*\"| copy2s3 -dest s3a://xxxctest/dest/",
        RuleState.ACTIVE);
    Thread.sleep(2500);
    List<ActionInfo> actions = metaStore.getActionsByRuleId(ruleId);
    Assert.assertEquals(actions.size(), 0);
  }

  @Test(timeout = 45000)
  public void testOnS3() throws Exception {
    waitTillSSMExitSafeMode();
    MetaStore metaStore = ssm.getMetaStore();
    DistributedFileSystem dfs = cluster.getFileSystem();
    final String srcPath = "/src/";
    dfs.mkdirs(new Path(srcPath));
    List<String> sps = new ArrayList<>();
    // Write to src
    for (int i = 0; i < 3; i++) {
      // Create test files
      // Not 0 because this file may be not be truncated yet
      sps.add(srcPath + i);
      DFSTestUtil.createFile(dfs, new Path(srcPath + i),
          10, (short) 1, 1);
    }

    do {
      Thread.sleep(1000);
      if (metaStore.getFilesByPaths(sps).size() == sps.size()) {
        break;
      }
    } while (true);

    for (String p : sps) {
      metaStore.insertUpdateFileState(new S3FileState(p));
    }
    long ruleId = ssm.getRuleManager().submitRule(
        "file: path matches \"/src/*\"| copy2s3 -dest s3a://xxxctest/dest/",
        RuleState.ACTIVE);
    Thread.sleep(2500);
    List<ActionInfo> actions = metaStore.getActionsByRuleId(ruleId);
    Assert.assertEquals(0, actions.size());
  }
}
