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

import org.apache.hadoop.conf.Configuration;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.smartdata.client.SmartClient;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.metastore.MetaStore;
import org.smartdata.model.FileState;
import org.smartdata.model.NormalFileState;

public class TestSmartClient extends MiniSmartClusterHarness {

  @Test
  @Ignore("Fails on CI, no success reproducing it locally")
  public void testGetFileState() throws Exception {
    waitTillSSMExitSafeMode();

    MetaStore metaStore = ssm.getMetaStore();
    String path = "/file1";
    FileState fileState = new NormalFileState(path);

    FileState fileState1;
    try (SmartClient client = new SmartClient(smartContext.getConf())) {
      // No entry in file_state table (Normal type as default)
      fileState1 = client.getFileState(path);
      Assert.assertEquals(fileState, fileState1);

      metaStore.insertUpdateFileState(fileState);
      fileState1 = client.getFileState(path);
      Assert.assertEquals(fileState, fileState1);
    }
  }

  @Test
  public void testDataIgnoreAndCover() throws Exception {
    waitTillSSMExitSafeMode();
    // Configuration can also be used for initializing SmartClient.
    Configuration conf = new Configuration();
    conf.set(SmartConfKeys.SMART_IGNORE_DIRS_KEY, "/test1");
    conf.set(SmartConfKeys.SMART_COVER_DIRS_KEY, "/test2");
    try (SmartClient client = new SmartClient(conf)) {
      Assert.assertTrue("This test file should be ignored",
          client.shouldIgnore("/test1/a.txt"));
      Assert.assertFalse("This test file should not be ignored",
          client.shouldIgnore("/test2/b.txt"));
    }
  }
}
