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
package org.smartdata.metastore.dao;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.exception.NotFoundException;
import org.smartdata.metastore.model.AggregatedAccessCounts;
import org.smartdata.metastore.queries.sort.CachedFilesSortField;
import org.smartdata.model.CachedFileStatus;
import org.smartdata.model.TimeInterval;
import org.smartdata.model.request.CachedFileSearchRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TestCacheFileDao extends TestSearchableDao<
    CachedFileSearchRequest, CachedFileStatus, CachedFilesSortField, Long> {

  private static final long FIRST_FILE_ID = 1L;
  private static final long SECOND_FILE_ID = 2L;
  private static final long THIRD_FILE_ID = 3L;

  private CacheFileDao cacheFileDao;

  @Before
  public void initCacheFileDao() {
    cacheFileDao = daoProvider.cacheFileDao();
  }

  @Test
  public void testUpdateCachedFiles() {
    CachedFileStatus first = new CachedFileStatus(80L,
        "testPath", 1000L, 2000L, 100);
    cacheFileDao.insert(first);
    CachedFileStatus second = new CachedFileStatus(90L,
        "testPath2", 2000L, 3000L, 200);
    cacheFileDao.insert(second);
    List<AggregatedAccessCounts> accessCounts = new ArrayList<>();
    accessCounts.add(new AggregatedAccessCounts(80L, 2,  4000L));
    accessCounts.add(new AggregatedAccessCounts(90L,  2, 5000L));
    accessCounts.add(new AggregatedAccessCounts(100L, 2, 9000L));

    // Sync status
    first = new CachedFileStatus(80L,
        "testPath", 1000L, 4000L, first.getNumAccessed() + 2);
    second = new CachedFileStatus(90L,
        "testPath2", 2000L, 5000L, second.getNumAccessed() + 2);

    cacheFileDao.update(accessCounts);
    List<CachedFileStatus> statuses = cacheFileDao.getAll();
    Assert.assertEquals(2, statuses.size());
    Map<Long, CachedFileStatus> statusMap = new HashMap<>();
    for (CachedFileStatus status : statuses) {
      statusMap.put(status.getFid(), status);
    }
    Assert.assertTrue(statusMap.containsKey(80L));
    CachedFileStatus dbFirst = statusMap.get(80L);
    Assert.assertEquals(first, dbFirst);
    Assert.assertTrue(statusMap.containsKey(90L));
    CachedFileStatus dbSecond = statusMap.get(90L);
    Assert.assertEquals(second, dbSecond);
  }

  @Test
  public void testInsertDeleteCachedFiles() throws NotFoundException {
    cacheFileDao
        .insert(80L,
            "testPath", 123456L, 234567L, 456);
    Assert.assertEquals(123456L, cacheFileDao.getById(
        80L).getFromTime());
    // Update record with 80l id
    cacheFileDao.update(80L,
        123455L, 460);
    Assert.assertEquals(123455L, cacheFileDao
        .getAll().get(0)
        .getLastAccessTime());
    List<CachedFileStatus> cachedFileStatuses = Collections.singletonList(
        new CachedFileStatus(321L, "testPath",
            113334L, 222222L, 222));
    cacheFileDao.insert(cachedFileStatuses);
    Assert.assertEquals(cachedFileStatuses.get(0), cacheFileDao.getById(321L));
    Assert.assertEquals(2, cacheFileDao.getAll().size());
    // Delete one record
    cacheFileDao.deleteById(321L);
    Assert.assertEquals(1, cacheFileDao.getAll().size());
    // Clear all records
    cacheFileDao.deleteAll();
    Assert.assertTrue(cacheFileDao.getAll().isEmpty());
  }

  @Test
  public void testGetCachedFileStatus() throws NotFoundException {
    cacheFileDao.insert(6L, "testPath", 1490918400000L,
        234567L, 456);
    CachedFileStatus cachedFileStatus = new CachedFileStatus(6L, "testPath", 1490918400000L,
        234567L, 456);
    cacheFileDao.insert(19L, "testPath", 1490918400000L,
        234567L, 456);
    cacheFileDao.insert(23L, "testPath", 1490918400000L,
        234567L, 456);
    CachedFileStatus dbcachedFileStatus = cacheFileDao.getById(6);
    Assert.assertEquals(cachedFileStatus, dbcachedFileStatus);
    List<CachedFileStatus> cachedFileList = cacheFileDao.getAll();
    List<Long> fids = cacheFileDao.getFids();
    Assert.assertEquals(3, fids.size());
    Assert.assertEquals(6, cachedFileList.get(0).getFid());
    Assert.assertEquals(19, cachedFileList.get(1).getFid());
    Assert.assertEquals(23, cachedFileList.get(2).getFid());
  }

  @Test
  public void testSearchWithoutFilters() {
    createTestCachedFiles();

    testSearch(CachedFileSearchRequest.noFilters(),
        FIRST_FILE_ID, SECOND_FILE_ID, THIRD_FILE_ID);
  }

  @Test
  public void testSearchByPath() {
    createTestCachedFiles();

    CachedFileSearchRequest request = CachedFileSearchRequest.builder()
        .pathLike("/src/")
        .build();

    testSearch(request, FIRST_FILE_ID, THIRD_FILE_ID);

    request = CachedFileSearchRequest.builder()
        .pathLike("/des")
        .build();

    testSearch(request, SECOND_FILE_ID);

    request = CachedFileSearchRequest.builder()
        .pathLike("/another_dir")
        .build();

    testSearch(request);
  }

  @Test
  public void testSearchByCachedTime() {
    createTestCachedFiles();

    CachedFileSearchRequest request = CachedFileSearchRequest.builder()
        .cachedTime(TimeInterval.ofEpochMillis(0L, 1000L))
        .build();

    testSearch(request,
        FIRST_FILE_ID, SECOND_FILE_ID, THIRD_FILE_ID);

    request = CachedFileSearchRequest.builder()
        .cachedTime(TimeInterval.ofEpochMillis(2L, 5L))
        .build();

    testSearch(request, SECOND_FILE_ID, THIRD_FILE_ID);

    request = CachedFileSearchRequest.builder()
        .cachedTime(TimeInterval.ofEpochMillis(6L, 500L))
        .build();

    testSearch(request);
  }

  @Test
  public void testSearchByLastAccessedTime() {
    createTestCachedFiles();

    CachedFileSearchRequest request = CachedFileSearchRequest.builder()
        .lastAccessedTime(TimeInterval.ofEpochMillis(0L, 1000L))
        .build();

    testSearch(request,
        FIRST_FILE_ID, SECOND_FILE_ID, THIRD_FILE_ID);

    request = CachedFileSearchRequest.builder()
        .lastAccessedTime(TimeInterval.ofEpochMillis(10L, 17L))
        .build();

    testSearch(request, FIRST_FILE_ID, THIRD_FILE_ID);

    request = CachedFileSearchRequest.builder()
        .cachedTime(TimeInterval.ofEpochMillis(18L, 500L))
        .build();

    testSearch(request);
  }

  private void createTestCachedFiles() {
    CachedFileStatus file1 = CachedFileStatus.builder()
        .fid(FIRST_FILE_ID)
        .path("/src/dir/tmp.log")
        .fromTime(1L)
        .lastAccessTime(12L)
        .numAccessed(12)
        .build();
    cacheFileDao.insert(file1);

    CachedFileStatus file2 = CachedFileStatus.builder()
        .fid(SECOND_FILE_ID)
        .path("/dest/etc/test.java")
        .fromTime(2L)
        .lastAccessTime(9L)
        .numAccessed(9)
        .build();
    cacheFileDao.insert(file2);

    CachedFileStatus file3 = CachedFileStatus.builder()
        .fid(THIRD_FILE_ID)
        .path("/src/third.txt")
        .fromTime(5L)
        .lastAccessTime(17L)
        .numAccessed(5)
        .build();
    cacheFileDao.insert(file3);
  }

  @Override
  protected Searchable<
      CachedFileSearchRequest, CachedFileStatus, CachedFilesSortField> searchable() {
    return cacheFileDao;
  }

  @Override
  protected Long getIdentifier(CachedFileStatus cachedFileStatus) {
    return cachedFileStatus.getFid();
  }

  @Override
  protected CachedFilesSortField defaultSortField() {
    return CachedFilesSortField.FILE_ID;
  }
}
