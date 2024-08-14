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
package org.smartdata.metastore.dao.accesscount;

import org.junit.Before;
import org.junit.Test;
import org.smartdata.metastore.TestDaoBase;
import org.smartdata.metastore.accesscount.DbAccessEventAggregator;
import org.smartdata.metastore.accesscount.FileAccessManager;
import org.smartdata.metastore.accesscount.failover.AccessCountContext;
import org.smartdata.metastore.accesscount.failover.Failover;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.FileAccessInfoSortField;
import org.smartdata.metastore.queries.sort.Sorting;
import org.smartdata.metastore.transaction.TransactionRunner;
import org.smartdata.metrics.FileAccessEvent;
import org.smartdata.model.FileAccessInfo;
import org.smartdata.model.FileInfo;
import org.smartdata.model.request.FileAccessInfoSearchRequest;
import org.testcontainers.shaded.com.google.common.collect.ImmutableMap;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class TestAccessEventAggregator extends TestDaoBase {

  private static final Map<String, Long> FILE_PATH_IDS = ImmutableMap.of(
      "/file1", 1L,
      "/file2", 2L,
      "/file3", 3L,
      "/file4", 4L
  );
  private FileAccessManager dbTableManager;
  private DbAccessEventAggregator aggregator;

  @Before
  public void setup() {
    dbTableManager =
        new FileAccessManager(new TransactionRunner(metaStore.transactionManager()),
            metaStore.accessCountEventDao(),
            metaStore.cacheFileDao());
    aggregator =
        new DbAccessEventAggregator(metaStore.fileInfoDao(),
            dbTableManager, new Failover<AccessCountContext>(){});
    metaStore.fileInfoDao().insert(testFileInfos());
  }

  @Test
  public void testAggregateEvents() {
    long currentTimeMs = System.currentTimeMillis();
    aggregator.aggregate(Collections.singletonList(new FileAccessEvent("", currentTimeMs)));
    aggregator.aggregate(Collections.singletonList
        (new FileAccessEvent("/file1", currentTimeMs + 1)));
    aggregator.aggregate(Collections.singletonList(
        new FileAccessEvent("", currentTimeMs + 1000)));
    aggregator.aggregate(
        Arrays.asList(
            new FileAccessEvent("/file1", currentTimeMs + 2000),
            new FileAccessEvent("/file1", currentTimeMs + 7999),
            new FileAccessEvent("/file1", currentTimeMs + 8000),
            new FileAccessEvent("/file2", currentTimeMs + 14000),
            new FileAccessEvent("/file3", currentTimeMs + 14000),
            new FileAccessEvent("/file3", currentTimeMs + 14001),
            new FileAccessEvent("/file3", currentTimeMs + 14002),
            new FileAccessEvent("/unknown_file", currentTimeMs + 14003),
            new FileAccessEvent("/file4", currentTimeMs + 16000),
            new FileAccessEvent("", currentTimeMs + 22000)));

    SearchResult<FileAccessInfo> fileAccessInfos =
        dbTableManager.search(FileAccessInfoSearchRequest.noFilters(),
            PageRequest.<FileAccessInfoSortField>builder()
                .addSorting(FileAccessInfoSortField.FID, Sorting.Order.ASC)
                .build());
    assertEquals(Arrays.asList(
            new FileAccessInfo(FILE_PATH_IDS.get("/file1"), "/file1", 4, currentTimeMs + 8000),
            new FileAccessInfo(FILE_PATH_IDS.get("/file2"), "/file2", 1, currentTimeMs + 14000),
            new FileAccessInfo(FILE_PATH_IDS.get("/file3"), "/file3", 3, currentTimeMs + 14002),
            new FileAccessInfo(FILE_PATH_IDS.get("/file4"), "/file4", 1, currentTimeMs + 16000)),
        fileAccessInfos.getItems());
  }

  private FileInfo[] testFileInfos() {
    return FILE_PATH_IDS.entrySet()
        .stream()
        .map(entry -> dummyFileInfo(entry.getKey(), entry.getValue()))
        .toArray(FileInfo[]::new);
  }

  private FileInfo dummyFileInfo(String path, long fileId) {
    return FileInfo.newBuilder()
        .setPath(path)
        .setFileId(fileId)
        .build();
  }
}
