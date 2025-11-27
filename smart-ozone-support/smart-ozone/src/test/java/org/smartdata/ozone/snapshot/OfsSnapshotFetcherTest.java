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

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class OfsSnapshotFetcherTest {

  @Test
  public void testExtractOriginalFilePath() {
    testExtractOriginalFilePath("/vol/buck/.snapshot/sn1/key", "/vol/buck/key");
    testExtractOriginalFilePath("/vol/buck/.snapshot/sn1/dir/key", "/vol/buck/dir/key");
    testExtractOriginalFilePath("/vol/buck/.snapshot/sn1/dir/subdir/key",
        "/vol/buck/dir/subdir/key");

    testExtractOriginalFilePath("ofs://host:123/vol/buck/.snapshot/sn1/dir/key",
        "ofs://host:123/vol/buck/dir/key");

    testExtractOriginalFilePath("/", "/");
    testExtractOriginalFilePath("/vol", "/vol");
    testExtractOriginalFilePath("/vol/buck", "/vol/buck");
  }

  private void testExtractOriginalFilePath(String sourcePath, String expectedPath) {
    try (OfsSnapshotFetcher fetcher = emptyFetcher()) {
      Path actualPath = fetcher.getOriginalFilePath(new Path(sourcePath));
      assertEquals(expectedPath, actualPath.toString());
    }
  }

  private OfsSnapshotFetcher emptyFetcher() {
    return OfsSnapshotFetcher.builder()
        .conf(new OzoneConfiguration())
        .batchSize(1)
        .build();
  }
}