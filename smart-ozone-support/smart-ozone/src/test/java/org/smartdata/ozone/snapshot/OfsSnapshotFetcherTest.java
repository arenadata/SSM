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
package org.smartdata.ozone.snapshot;

import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.Path;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.ozone.MiniOzoneClusterHarness;
import org.smartdata.ozone.model.FsObjectStreamRecord;

import java.io.IOException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class OfsSnapshotFetcherTest extends MiniOzoneClusterHarness {
  private static final int BATCH_SIZE = 1024;
  private static final int TIMEOUT_MS = 5000;

  private OfsSnapshotFetcher fetcher;

  @Before
  public void initFiles() {
//    ofs.createFile(new Path("/test.txt"));

    fetcher = new OfsSnapshotFetcher(
        ofs, Executors.newSingleThreadExecutor(), BATCH_SIZE);
  }

  @After
  public void close() {
    if (fetcher != null) {
      fetcher.close();
    }
  }

  //  @Test
  public void testFetchSnapshot() throws InterruptedException {
    fetcher.runSnapshotAsync().wait(TIMEOUT_MS);

    BlockingQueue<FsObjectStreamRecord> outputQueue = fetcher.getOutputQueue();
    assertEquals(1, outputQueue.size());
  }

  @Test
  public void test() throws IOException {
    ofs.mkdirs(new Path("/vol1"));
    ofs.mkdirs(new Path("/vol1", "bucket1"));

    try (FSDataOutputStream os = ofs.create(new Path("/vol1/buck1/test"))) {
      os.writeBytes("test");
    }

    assertTrue(ofs.exists(new Path("/vol1/buck1/test")));
  }
}