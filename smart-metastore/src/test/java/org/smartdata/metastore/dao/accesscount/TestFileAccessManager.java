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
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.accesscount.FileAccessManager;
import org.smartdata.metastore.dao.Searchable;
import org.smartdata.metastore.dao.TestSearchableDao;
import org.smartdata.metastore.model.AggregatedAccessCounts;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.metastore.partition.FileAccessPartitionManager;
import org.smartdata.metastore.partition.FileAccessPartitionManagerImpl;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.FileAccessInfoSortField;
import org.smartdata.metastore.queries.sort.Sorting;
import org.smartdata.metastore.transaction.TransactionRunner;
import org.smartdata.model.FileAccessInfo;
import org.smartdata.model.FileInfo;
import org.smartdata.model.TimeInterval;
import org.smartdata.model.request.FileAccessInfoSearchRequest;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.IntStream;

import static org.junit.Assert.assertEquals;

public class TestFileAccessManager extends
    TestSearchableDao<FileAccessInfoSearchRequest, FileAccessInfo, FileAccessInfoSortField, Long> {

  private static final List<String> TEST_FILES = Arrays.asList(
      "/file0",
      "/file1",
      "/file2",
      "/file3",
      "/file4",
      "/file5"
  );
  private FileAccessManager fileAccessManager;

  @Before
  public void setUp() {
    FileAccessPartitionManager fileAccessPartitionManager =
        new FileAccessPartitionManagerImpl(metaStore);
    fileAccessPartitionManager.createNewPartitions();
    fileAccessManager = new FileAccessManager(
        new TransactionRunner(metaStore.transactionManager()),
        metaStore.accessCountEventDao(),
        metaStore.cacheFileDao());
  }

  @Override
  protected Searchable<FileAccessInfoSearchRequest, FileAccessInfo, FileAccessInfoSortField> searchable() {
    return fileAccessManager;
  }

  @Override
  protected Long getIdentifier(FileAccessInfo fileAccessInfo) {
    return fileAccessInfo.getFid();
  }

  @Override
  protected FileAccessInfoSortField defaultSortField() {
    return FileAccessInfoSortField.FID;
  }

  @Test
  public void testSaveAccessCounts() throws MetaStoreException {
    long currentTimeMillis = System.currentTimeMillis();
    insertFileAccessCounts(currentTimeMillis);

    SearchResult<FileAccessInfo> fileAccessInfos =
        fileAccessManager.search(FileAccessInfoSearchRequest.noFilters(),
            PageRequest.<FileAccessInfoSortField>builder()
                .addSorting(FileAccessInfoSortField.FID, Sorting.Order.ASC)
                .build());
    assertEquals(Arrays.asList(new FileAccessInfo(1, TEST_FILES.get(1), 3, currentTimeMillis + 2),
            new FileAccessInfo(2, TEST_FILES.get(2), 1, currentTimeMillis + 2),
            new FileAccessInfo(3, TEST_FILES.get(3), 2, currentTimeMillis + 3)),
        fileAccessInfos.getItems());
  }

  @Test
  public void testSearchByIds() throws MetaStoreException {
    List<Long> ids = Arrays.asList(1L, 2L);
    long currentTimeMillis = System.currentTimeMillis();
    insertFileAccessCounts(currentTimeMillis);
    testSearch(FileAccessInfoSearchRequest.builder().ids(ids).build(), 1L, 2L);
  }

  @Test
  public void testSearchByPath() throws MetaStoreException {
    long currentTimeMillis = System.currentTimeMillis();
    insertFileAccessCounts(currentTimeMillis);
    testSearch(FileAccessInfoSearchRequest.builder()
            .pathLike("/file3")
            .build(),
        3L);
    testSearch(FileAccessInfoSearchRequest.builder()
            .pathLike("/file")
            .build(),
        1L, 2L, 3L);
  }

  @Test
  public void testSearchByLastAccessTime() throws MetaStoreException {
    long currentTimeMillis = System.currentTimeMillis();
    insertFileAccessCounts(currentTimeMillis);

    testSearch(FileAccessInfoSearchRequest.builder()
            .lastAccessedTime(TimeInterval.builder()
                .from(Instant.ofEpochMilli(currentTimeMillis))
                .to(Instant.ofEpochMilli(currentTimeMillis + 2))
                .build())
            .build(),
        1L, 2L);
  }

  private void insertFileAccessCounts(long currentTimeMillis) throws MetaStoreException {
    createTestFiles();
    Collection<AggregatedAccessCounts> accessCounts = Arrays.asList(
        new AggregatedAccessCounts(1, 1, currentTimeMillis),
        new AggregatedAccessCounts(1, 1, currentTimeMillis + 1),
        new AggregatedAccessCounts(1, 1, currentTimeMillis + 2),
        new AggregatedAccessCounts(2, 1, currentTimeMillis + 2),
        new AggregatedAccessCounts(3, 1, currentTimeMillis + 2),
        new AggregatedAccessCounts(3, 1, currentTimeMillis + 3)
    );
    metaStore.accessCountEventDao().insert(accessCounts);
  }

  private void createTestFiles() throws MetaStoreException {
    FileInfo[] fileInfos = IntStream.range(0, TEST_FILES.size())
        .mapToObj(id -> FileInfo.newBuilder()
            .setFileId(id)
            .setPath(TEST_FILES.get(id))
            .build())
        .toArray(FileInfo[]::new);

    metaStore.insertFiles(fileInfos);
  }
}
