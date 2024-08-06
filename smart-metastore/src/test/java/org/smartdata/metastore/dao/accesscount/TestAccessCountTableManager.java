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

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.conf.SmartConf;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.dao.Searchable;
import org.smartdata.metastore.dao.TestSearchableDao;
import org.smartdata.metastore.model.AccessCountTable;
import org.smartdata.metastore.model.AggregatedAccessCounts;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.FileAccessInfoSortField;
import org.smartdata.metastore.queries.sort.Sorting;
import org.smartdata.metastore.utils.Constants;
import org.smartdata.metastore.utils.TimeGranularity;
import org.smartdata.metrics.FileAccessEvent;
import org.smartdata.model.FileAccessInfo;
import org.smartdata.model.FileInfo;
import org.smartdata.model.TimeInterval;
import org.smartdata.model.request.FileAccessInfoSearchRequest;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.IntStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.smartdata.conf.SmartConfKeys.SMART_ACCESS_COUNT_AGGREGATION_INTERVAL_MS_DEFAULT;
import static org.smartdata.metastore.utils.Constants.ONE_DAY_IN_MILLIS;
import static org.smartdata.metastore.utils.Constants.ONE_HOUR_IN_MILLIS;
import static org.smartdata.metastore.utils.Constants.ONE_MINUTE_IN_MILLIS;
import static org.smartdata.metastore.utils.Constants.ONE_SECOND_IN_MILLIS;


public class TestAccessCountTableManager
    extends TestSearchableDao<FileAccessInfoSearchRequest, FileAccessInfo, FileAccessInfoSortField, Long> {

  private static final List<String> TEST_FILES = Arrays.asList(
      "/file0",
      "/file1",
      "/file2",
      "/file3",
      "/file4",
      "/file5"
  );

  private AccessCountTableManager accessCountTableManager;
  private InMemoryAccessCountTableManager inMemoryTableManager;
  private ExecutorService executorService;

  @Before
  public void setup() {
    executorService = Executors.newFixedThreadPool(4);
    accessCountTableManager = new AccessCountTableManager(
        metaStore, executorService, new SmartConf()
    );
    inMemoryTableManager = accessCountTableManager.getInMemoryTableManager();
  }

  @After
  public void shutDown() {
    executorService.shutdownNow();
  }

  @Override
  protected Searchable<FileAccessInfoSearchRequest, FileAccessInfo, FileAccessInfoSortField> searchable() {
    return accessCountTableManager;
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
  public void testSearchByFilePath() throws MetaStoreException {
    createTestFiles();

    List<FileAccessEvent> accessEvents = Arrays.asList(
        new FileAccessEvent("/file1", 1),
        new FileAccessEvent("/file2", 3),
        new FileAccessEvent("/file4", 4),
        new FileAccessEvent("/file2", 5),
        new FileAccessEvent("", 5001)
    );
    accessCountTableManager.getAccessEventAggregator().aggregate(accessEvents);

    FileAccessInfoSearchRequest searchRequest = FileAccessInfoSearchRequest.builder()
        .pathLike("/file")
        .build();

    testSearch(searchRequest, 1L, 2L, 4L);

    searchRequest = FileAccessInfoSearchRequest.builder()
        .pathLike("/file2")
        .build();

    testSearch(searchRequest, 2L);

    searchRequest = FileAccessInfoSearchRequest.builder()
        .pathLike("another_path")
        .build();

    testSearch(searchRequest);
  }

  @Test
  public void testCreateTable() throws Exception {
    long firstDayEnd = 24 * 60 * 60 * 1000L;
    AccessCountTable accessCountTable =
        new AccessCountTable(firstDayEnd - 5 * 1000, firstDayEnd);
    accessCountTableManager.createTable(accessCountTable);

    Thread.sleep(5000);

    Deque<AccessCountTable> second =
        inMemoryTableManager.getTablesOfGranularity(TimeGranularity.SECOND);

    assertEquals(1, second.size());
    assertEquals(accessCountTable, second.peek());

    Deque<AccessCountTable> minute =
        inMemoryTableManager.getTablesOfGranularity(TimeGranularity.MINUTE);
    AccessCountTable minuteTable =
        new AccessCountTable(firstDayEnd - 60 * 1000, firstDayEnd);
    assertEquals(1, minute.size());
    assertEquals(minuteTable, minute.peek());

    Deque<AccessCountTable> hour =
        inMemoryTableManager.getTablesOfGranularity(TimeGranularity.HOUR);
    AccessCountTable hourTable =
        new AccessCountTable(firstDayEnd - 60 * 60 * 1000, firstDayEnd);
    assertEquals(1, hour.size());
    assertEquals(hourTable, hour.peek());

    Deque<AccessCountTable> day =
        inMemoryTableManager.getTablesOfGranularity(TimeGranularity.DAY);
    AccessCountTable dayTable = new AccessCountTable(0, firstDayEnd);
    assertEquals(1, day.size());
    assertEquals(dayTable, day.peek());
  }

  @Test
  public void testGetTables() throws MetaStoreException {
    AccessCountTable firstDay = new AccessCountTable(0L, Constants.ONE_DAY_IN_MILLIS);

    AccessCountTable firstHour =
        new AccessCountTable(23 * Constants.ONE_HOUR_IN_MILLIS,
            24 * Constants.ONE_HOUR_IN_MILLIS);
    AccessCountTable secondHour =
        new AccessCountTable(24 * Constants.ONE_HOUR_IN_MILLIS,
            25 * Constants.ONE_HOUR_IN_MILLIS);

    int numMins = 25 * 60;
    AccessCountTable firstMin =
        new AccessCountTable(
            (numMins - 1) * ONE_MINUTE_IN_MILLIS,
            numMins * ONE_MINUTE_IN_MILLIS);
    AccessCountTable secondMin =
        new AccessCountTable(
            numMins * ONE_MINUTE_IN_MILLIS,
            (numMins + 1) * ONE_MINUTE_IN_MILLIS);

    int numSeconds = (25 * 60 + 1) * 60;
    AccessCountTable firstFiveSeconds =
        new AccessCountTable(
            (numSeconds - 5) * Constants.ONE_SECOND_IN_MILLIS,
            numSeconds * Constants.ONE_SECOND_IN_MILLIS);
    AccessCountTable secondFiveSeconds =
        new AccessCountTable(
            numSeconds * Constants.ONE_SECOND_IN_MILLIS,
            (numSeconds + 5) * Constants.ONE_SECOND_IN_MILLIS);

    accessCountTableManager.getDbTableManager().createTable(firstDay);

    List<AccessCountTable> tablesToRecover = Arrays.asList(
        firstDay, firstHour, secondHour, firstMin, secondMin, firstFiveSeconds, secondFiveSeconds);
    inMemoryTableManager.recoverTables(tablesToRecover);
    /*
    |------------------------interval----------------------------|
                                                         |-s-|-s-|
                                             |---m---|---m---|
                      |-------h-------|-------h------|
    |---------------d-----------------|
    */
    List<AccessCountTable> firstResult =
        accessCountTableManager.getTablesForLast(
            (numSeconds + 5) * Constants.ONE_SECOND_IN_MILLIS);
    assertEquals(4, firstResult.size());
    assertEquals(firstDay, firstResult.get(0));
    assertEquals(secondHour, firstResult.get(1));
    assertEquals(secondMin, firstResult.get(2));
    assertEquals(secondFiveSeconds, firstResult.get(3));

    /*
        |--------------------interval----------------------------|
                                                         |-s-|-s-|
                                             |---m---|---m---|
                      |-------h-------|-------h------|
    |---------------d-----------------|
    */
    List<AccessCountTable> secondResult =
        accessCountTableManager.getTablesForLast(
            numSeconds * Constants.ONE_SECOND_IN_MILLIS);
    assertEquals(5, secondResult.size());

    AccessCountTable firstTable = secondResult.get(0);
    assertTrue(firstTable.getStartTime() == 5 * Constants.ONE_SECOND_IN_MILLIS
        && firstTable.getEndTime() == 23 * Constants.ONE_HOUR_IN_MILLIS);

   /*
                      |--------------interval--------------------|
                                                         |-s-|-s-|
                                             |---m---|---m---|
                      |-------h-------|-------h------|
    |---------------d-----------------|
    */
    List<AccessCountTable> thirdResult =
        accessCountTableManager.getTablesForLast(
            secondFiveSeconds.getEndTime() - 23 * Constants.ONE_HOUR_IN_MILLIS);
    assertEquals(4, thirdResult.size());
    assertEquals(firstHour, thirdResult.get(0));

    /*
                                      |--------interval----------|
                                                         |-s-|-s-|
                                             |---m---|---m---|
                      |-------h-------|-------h------|
    |---------------d-----------------|
    */
    List<AccessCountTable> fourthResult =
        accessCountTableManager.getTablesForLast(
            secondFiveSeconds.getEndTime() - 24 * Constants.ONE_HOUR_IN_MILLIS);
    assertEquals(3, fourthResult.size());
    assertEquals(secondHour, fourthResult.get(0));
  }

  @Test
  public void testGetTablesCornerCase() throws MetaStoreException {
    AccessCountTable firstFiveSeconds =
        new AccessCountTable(0L, 5 * Constants.ONE_SECOND_IN_MILLIS);
    AccessCountTable secondFiveSeconds =
        new AccessCountTable(5 * Constants.ONE_SECOND_IN_MILLIS,
            10 * Constants.ONE_SECOND_IN_MILLIS);

    List<AccessCountTable> tablesToRecover =
        Arrays.asList(firstFiveSeconds, secondFiveSeconds);
    inMemoryTableManager.recoverTables(tablesToRecover);

    List<AccessCountTable> result = accessCountTableManager.getTablesForLast(
        2 * ONE_MINUTE_IN_MILLIS);
    assertEquals(2, result.size());
    assertEquals(firstFiveSeconds, result.get(0));
    assertEquals(secondFiveSeconds, result.get(1));
  }

  @Test
  public void testGetTablesCornerCaseMinutes() throws MetaStoreException {
    /*
           |--interval-|
           |-s-|-s-|-s-|
    |----m-----|
    */
    AccessCountTable firstMinute =
        new AccessCountTable(0L, ONE_MINUTE_IN_MILLIS);
    AccessCountTable firstFiveSeconds =
        new AccessCountTable(
            55 * Constants.ONE_SECOND_IN_MILLIS, 60 * Constants.ONE_SECOND_IN_MILLIS);
    AccessCountTable secondFiveSeconds =
        new AccessCountTable(60 * Constants.ONE_SECOND_IN_MILLIS,
            65 * Constants.ONE_SECOND_IN_MILLIS);
    AccessCountTable thirdFiveSeconds =
        new AccessCountTable(110 * Constants.ONE_SECOND_IN_MILLIS,
            115 * Constants.ONE_SECOND_IN_MILLIS);

    List<AccessCountTable> tablesToRecover = Arrays.asList(
        firstMinute, firstFiveSeconds, secondFiveSeconds, thirdFiveSeconds);

    inMemoryTableManager.recoverTables(tablesToRecover);

    List<AccessCountTable> result = accessCountTableManager.getTablesForLast(
        ONE_MINUTE_IN_MILLIS);

    assertEquals(3, result.size());
    assertEquals(firstFiveSeconds, result.get(0));
    Assert.assertFalse(result.get(0).isEphemeral());
    assertEquals(secondFiveSeconds, result.get(1));
    assertEquals(thirdFiveSeconds, result.get(2));
  }

  @Test
  public void testGetAllHotFiles() throws MetaStoreException {
    createTestFiles();
    /*
    create access count tables for seconds, day and hours intervals
    |-------------------------------------interval-----------------------------------------------|
    |-s-| |-s-| |-s-| |-s-| |-s-| |-s-| |-s-|       |-s-|   |-s-|      |-s-|   |-s-|     |-s-|
                                                  |---h---|---h----| |---h---|---h---|
    |-----------------------d-----------------|
     */
    DbAccessCountTableManager tableManager = accessCountTableManager.getDbTableManager();
    AccessCountTable t1 = new AccessCountTable(0, 5 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t2 = new AccessCountTable(2 * ONE_MINUTE_IN_MILLIS,
        2 * ONE_MINUTE_IN_MILLIS + 5 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t3 = new AccessCountTable(4 * ONE_MINUTE_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS,
        4 * ONE_MINUTE_IN_MILLIS + 15 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t4 = new AccessCountTable(ONE_HOUR_IN_MILLIS + 5 * ONE_MINUTE_IN_MILLIS,
        ONE_HOUR_IN_MILLIS + 5 * ONE_MINUTE_IN_MILLIS + 5 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t5 = new AccessCountTable(ONE_HOUR_IN_MILLIS + 9 * ONE_MINUTE_IN_MILLIS,
        ONE_HOUR_IN_MILLIS + 9 * ONE_MINUTE_IN_MILLIS + 5 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t6 = new AccessCountTable(8 * ONE_HOUR_IN_MILLIS,
        8 * ONE_HOUR_IN_MILLIS + 5 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t7 = new AccessCountTable(ONE_DAY_IN_MILLIS + 12 * ONE_HOUR_IN_MILLIS,
        ONE_DAY_IN_MILLIS + 12 * ONE_HOUR_IN_MILLIS + 5 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t8 = new AccessCountTable(
        ONE_DAY_IN_MILLIS + 13 * ONE_HOUR_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS,
        ONE_DAY_IN_MILLIS + 13 * ONE_HOUR_IN_MILLIS + 15 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t9 = new AccessCountTable(ONE_DAY_IN_MILLIS + 17 * ONE_HOUR_IN_MILLIS,
        ONE_DAY_IN_MILLIS + 17 * ONE_HOUR_IN_MILLIS + 5 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t10 = new AccessCountTable(
        ONE_DAY_IN_MILLIS + 18 * ONE_HOUR_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS,
        ONE_DAY_IN_MILLIS + 18 * ONE_HOUR_IN_MILLIS + 15 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t11 =
        new AccessCountTable(ONE_DAY_IN_MILLIS + 23 * ONE_HOUR_IN_MILLIS + 59 * ONE_MINUTE_IN_MILLIS
            + 58 * ONE_SECOND_IN_MILLIS, 2 * ONE_DAY_IN_MILLIS);
    AccessCountTable t12 = new AccessCountTable(0, ONE_DAY_IN_MILLIS);
    AccessCountTable t13 = new AccessCountTable(ONE_DAY_IN_MILLIS + 12 * ONE_HOUR_IN_MILLIS,
        ONE_DAY_IN_MILLIS + 13 * ONE_HOUR_IN_MILLIS);
    AccessCountTable t14 = new AccessCountTable(ONE_DAY_IN_MILLIS + 13 * ONE_HOUR_IN_MILLIS,
        ONE_DAY_IN_MILLIS + 14 * ONE_HOUR_IN_MILLIS);
    AccessCountTable t15 = new AccessCountTable(ONE_DAY_IN_MILLIS + 17 * ONE_HOUR_IN_MILLIS,
        ONE_DAY_IN_MILLIS + 18 * ONE_HOUR_IN_MILLIS);
    AccessCountTable t16 = new AccessCountTable(ONE_DAY_IN_MILLIS + 18 * ONE_HOUR_IN_MILLIS,
        ONE_DAY_IN_MILLIS + 19 * ONE_HOUR_IN_MILLIS);

    List<AccessCountTable> tables =
        Arrays.asList(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16);

    for (AccessCountTable t : tables) {
      tableManager.createTable(t);
    }
    tableManager.handleAggregatedEvents(t1,
        Arrays.asList(new AggregatedAccessCounts(0, 1, 0),
            new AggregatedAccessCounts(1, 1, 1)));
    tableManager.handleAggregatedEvents(t2,
        Arrays.asList(new AggregatedAccessCounts(2, 1, 2 * ONE_MINUTE_IN_MILLIS + 1)));
    tableManager.handleAggregatedEvents(t3, Arrays.asList(
        new AggregatedAccessCounts(1, 1, 4 * ONE_MINUTE_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t4, Arrays.asList(
        new AggregatedAccessCounts(2, 1, ONE_HOUR_IN_MILLIS + 5 * ONE_MINUTE_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t5, Arrays.asList(
        new AggregatedAccessCounts(3, 1, ONE_HOUR_IN_MILLIS + 9 * ONE_MINUTE_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t6,
        Arrays.asList(new AggregatedAccessCounts(3, 1, 8 * ONE_HOUR_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t7, Arrays.asList(
        new AggregatedAccessCounts(3, 1, ONE_DAY_IN_MILLIS + 12 * ONE_HOUR_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t7, Arrays.asList(
        new AggregatedAccessCounts(2, 1, ONE_DAY_IN_MILLIS + 12 * ONE_HOUR_IN_MILLIS + 1)));
    tableManager.handleAggregatedEvents(t8, Arrays.asList(new AggregatedAccessCounts(1, 1,
        ONE_DAY_IN_MILLIS + 13 * ONE_HOUR_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t9, Arrays.asList(
        new AggregatedAccessCounts(4, 1, ONE_DAY_IN_MILLIS + 17 * ONE_HOUR_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t10, Arrays.asList(
        new AggregatedAccessCounts(5, 1, ONE_DAY_IN_MILLIS + 18 * ONE_HOUR_IN_MILLIS + 10)));
    tableManager.handleAggregatedEvents(t11, Arrays.asList(
        new AggregatedAccessCounts(3, 1,
            ONE_DAY_IN_MILLIS + 23 * ONE_HOUR_IN_MILLIS + 59 * ONE_MINUTE_IN_MILLIS
                + 58 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t11, Arrays.asList(
        new AggregatedAccessCounts(3, 1,
            ONE_DAY_IN_MILLIS + 23 * ONE_HOUR_IN_MILLIS + 59 * ONE_MINUTE_IN_MILLIS
                + 59 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t12,
        Arrays.asList(
            new AggregatedAccessCounts(0, 1, 0),
            new AggregatedAccessCounts(1, 2, 4 * ONE_MINUTE_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS),
            new AggregatedAccessCounts(2, 2, ONE_HOUR_IN_MILLIS + 5 * ONE_MINUTE_IN_MILLIS),
            new AggregatedAccessCounts(3, 2, 8 * ONE_HOUR_IN_MILLIS)
        ));
    tableManager.handleAggregatedEvents(t13, Arrays.asList(
        new AggregatedAccessCounts(3, 1, ONE_DAY_IN_MILLIS + 12 * ONE_HOUR_IN_MILLIS),
        new AggregatedAccessCounts(2, 1, ONE_DAY_IN_MILLIS + 12 * ONE_HOUR_IN_MILLIS + 1)
    ));
    tableManager.handleAggregatedEvents(t14, Arrays.asList(new AggregatedAccessCounts(1, 1,
        ONE_DAY_IN_MILLIS + 13 * ONE_HOUR_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t15, Arrays.asList(
        new AggregatedAccessCounts(4, 1, ONE_DAY_IN_MILLIS + 17 * ONE_HOUR_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t16, Arrays.asList(
        new AggregatedAccessCounts(5, 1, ONE_DAY_IN_MILLIS + 18 * ONE_HOUR_IN_MILLIS + 10)));

    inMemoryTableManager.recoverTables(tables);

    List<FileAccessInfo> expectedFiles = Arrays.asList(
        new FileAccessInfo(0, TEST_FILES.get(0), 1, 0),
        new FileAccessInfo(1, TEST_FILES.get(1), 3,
            ONE_DAY_IN_MILLIS + 13 * ONE_HOUR_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(2, TEST_FILES.get(2), 3,
            ONE_DAY_IN_MILLIS + 12 * ONE_HOUR_IN_MILLIS + 1),
        new FileAccessInfo(3, TEST_FILES.get(3), 5,
            ONE_DAY_IN_MILLIS + 23 * ONE_HOUR_IN_MILLIS + 59 * ONE_MINUTE_IN_MILLIS
                + 59 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(4, TEST_FILES.get(4), 1, ONE_DAY_IN_MILLIS
            + 17 * ONE_HOUR_IN_MILLIS),
        new FileAccessInfo(5, TEST_FILES.get(5), 1,
            ONE_DAY_IN_MILLIS + 18 * ONE_HOUR_IN_MILLIS + 10)
    );

    Long latestAccessedTime = expectedFiles.stream()
        .min(Comparator.comparing(FileAccessInfo::getLastAccessedTime))
        .map(FileAccessInfo::getLastAccessedTime)
        .orElseThrow(NoSuchElementException::new);

    List<FileAccessInfo> hotFiles =
        accessCountTableManager.search(FileAccessInfoSearchRequest.builder()
                .lastAccessedTime(TimeInterval.builder()
                    .from(Instant.ofEpochMilli(latestAccessedTime))
                    .build())
                .build(),
            PageRequest.<FileAccessInfoSortField>builder()
                .addSorting(FileAccessInfoSortField.FID, Sorting.Order.ASC)
                .build()).getItems();

    assertEquals(expectedFiles, hotFiles);
  }

  @Test
  public void testGetAllHotFilesDuringLastSeconds() throws MetaStoreException {
    createTestFiles();
    submitAccessEvents();

    List<FileAccessInfo> expectedFiles = Arrays.asList(
        new FileAccessInfo(3, TEST_FILES.get(3), 2,
            ONE_DAY_IN_MILLIS + 23 * ONE_HOUR_IN_MILLIS + 59 * ONE_MINUTE_IN_MILLIS
                + 59 * ONE_SECOND_IN_MILLIS)
    );
    Long latestAccessedTime = expectedFiles.stream()
        .max(Comparator.comparing(FileAccessInfo::getLastAccessedTime))
        .map(FileAccessInfo::getLastAccessedTime)
        .orElseThrow(NoSuchElementException::new);

    List<FileAccessInfo> hotFiles =
        accessCountTableManager.search(FileAccessInfoSearchRequest.builder()
            .lastAccessedTime(TimeInterval.builder()
                .from(Instant.ofEpochMilli(latestAccessedTime - 5 * ONE_SECOND_IN_MILLIS))
                .to(Instant.ofEpochMilli(latestAccessedTime))
                .build())
            .build());

    assertEquals(expectedFiles, hotFiles);
  }

  @Test
  public void testGetHotFilesDuringLastHour() throws MetaStoreException {
    createTestFiles();
    submitAccessEvents();

    List<FileAccessInfo> expectedFiles = Collections.singletonList(
        new FileAccessInfo(3, TEST_FILES.get(3), 2,
            ONE_DAY_IN_MILLIS + 23 * ONE_HOUR_IN_MILLIS + 59 * ONE_MINUTE_IN_MILLIS
                + 59 * ONE_SECOND_IN_MILLIS)
    );

    Long latestAccessedTime = expectedFiles.stream()
        .max(Comparator.comparing(FileAccessInfo::getLastAccessedTime))
        .map(FileAccessInfo::getLastAccessedTime)
        .orElseThrow(NoSuchElementException::new);

    List<FileAccessInfo> hotFiles =
        accessCountTableManager.search(FileAccessInfoSearchRequest.builder()
            .lastAccessedTime(TimeInterval.builder()
                .from(Instant.ofEpochMilli(latestAccessedTime - ONE_HOUR_IN_MILLIS))
                .to(Instant.ofEpochMilli(latestAccessedTime))
                .build())
            .build());

    assertEquals(expectedFiles, hotFiles);
  }

  @Test
  public void testGetHotFilesFromPartialTable() throws MetaStoreException {
    createTestFiles();
    submitAccessEvents();

    List<FileAccessInfo> expectedFiles = Collections.singletonList(
        new FileAccessInfo(3, TEST_FILES.get(3), 1,
            ONE_DAY_IN_MILLIS + 23 * ONE_HOUR_IN_MILLIS + 59 * ONE_MINUTE_IN_MILLIS
                + 59 * ONE_SECOND_IN_MILLIS)
    );

    Long latestAccessedTime = expectedFiles.stream()
        .max(Comparator.comparing(FileAccessInfo::getLastAccessedTime))
        .map(FileAccessInfo::getLastAccessedTime)
        .orElseThrow(NoSuchElementException::new);

    List<FileAccessInfo> hotFiles =
        accessCountTableManager.search(FileAccessInfoSearchRequest.builder()
            .lastAccessedTime(TimeInterval.builder()
                .from(Instant.ofEpochMilli(
                    (latestAccessedTime - SMART_ACCESS_COUNT_AGGREGATION_INTERVAL_MS_DEFAULT / 2)))
                .to(Instant.ofEpochMilli(latestAccessedTime))
                .build())
            .build());

    assertEquals(expectedFiles, hotFiles);
  }

  @Test
  public void testGetHotFilesWhenIntervalBiggerThanExistedTables()
      throws MetaStoreException {
    /*
    |---------interval-------------|
         |-s-| |-s-| |-s-|
      |--------min--------------|
    */
    createTestFiles();
    DbAccessCountTableManager tableManager = accessCountTableManager.getDbTableManager();
    AccessCountTable t1 = new AccessCountTable(0, 5 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t2 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 5 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t3 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 20 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 25 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t4 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 35 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 40 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t5 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 45 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 50 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t6 = new AccessCountTable(ONE_MINUTE_IN_MILLIS, 2 * ONE_MINUTE_IN_MILLIS);
    List<AccessCountTable> tables = Arrays.asList(t1, t2, t3, t4, t5, t6);
    tables.forEach(t -> {
      try {
        tableManager.createTable(t);
      } catch (MetaStoreException e) {
        throw new RuntimeException(e);
      }
    });
    tableManager.handleAggregatedEvents(t1, Arrays.asList(new AggregatedAccessCounts(3, 1, 0)));
    tableManager.handleAggregatedEvents(t2, Arrays.asList(
        new AggregatedAccessCounts(3, 1, ONE_MINUTE_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t3, Arrays.asList(
        new AggregatedAccessCounts(2, 1, ONE_MINUTE_IN_MILLIS + 21 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 1, ONE_MINUTE_IN_MILLIS + 21 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t4, Arrays.asList(
        new AggregatedAccessCounts(5, 1, ONE_MINUTE_IN_MILLIS + 38 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t5, Arrays.asList(
        new AggregatedAccessCounts(1, 2, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 2, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 1, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 1, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 1, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    ));
    tableManager.handleAggregatedEvents(t6, Arrays.asList(
        new AggregatedAccessCounts(1, 4, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 2, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 2, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    ));
    inMemoryTableManager.recoverTables(tables);

    List<FileAccessInfo> expectedFiles = Arrays.asList(
        new FileAccessInfo(1, TEST_FILES.get(1), 4,
            ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(2, TEST_FILES.get(2), 3,
            ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(3, TEST_FILES.get(3), 3,
            ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(4, TEST_FILES.get(4), 2,
            ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(5, TEST_FILES.get(5), 2,
            ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    );

    List<FileAccessInfo> hotFiles =
        accessCountTableManager.search(FileAccessInfoSearchRequest.builder()
            .lastAccessedTime(TimeInterval.builder()
                .from(Instant.ofEpochMilli(55 * ONE_SECOND_IN_MILLIS))
                .to(Instant.ofEpochMilli(2 * ONE_MINUTE_IN_MILLIS + 5 * ONE_SECOND_IN_MILLIS))
                .build())
            .build());
    assertEquals(expectedFiles, hotFiles);
  }

  @Test
  public void testGetHotFilesWhenIntervalEndTimeLessThanRightBorderOfParentTable()
      throws MetaStoreException {
    /*
    |---------interval------|
         |-s-| |-s-| |-s-|
      |--------min--------------|
    */
    createTestFiles();
    DbAccessCountTableManager tableManager = accessCountTableManager.getDbTableManager();
    AccessCountTable t1 = new AccessCountTable(0, 5 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t2 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 5 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t3 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 20 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 25 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t4 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 35 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 40 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t5 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 45 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 50 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t6 = new AccessCountTable(ONE_MINUTE_IN_MILLIS, 2 * ONE_MINUTE_IN_MILLIS);
    List<AccessCountTable> tables = Arrays.asList(t1, t2, t3, t4, t5, t6);
    tables.forEach(t -> {
      try {
        tableManager.createTable(t);
      } catch (MetaStoreException e) {
        throw new RuntimeException(e);
      }
    });
    tableManager.handleAggregatedEvents(t1, Arrays.asList(new AggregatedAccessCounts(3, 1, 0)));
    tableManager.handleAggregatedEvents(t2, Arrays.asList(
        new AggregatedAccessCounts(3, 1, ONE_MINUTE_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t3, Arrays.asList(
        new AggregatedAccessCounts(2, 1, ONE_MINUTE_IN_MILLIS + 21 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 1, ONE_MINUTE_IN_MILLIS + 21 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t4, Arrays.asList(
        new AggregatedAccessCounts(5, 1, ONE_MINUTE_IN_MILLIS + 38 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t5, Arrays.asList(
        new AggregatedAccessCounts(1, 2, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 2, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 1, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 1, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 1, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    ));
    tableManager.handleAggregatedEvents(t6, Arrays.asList(
        new AggregatedAccessCounts(1, 4, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 2, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 2, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    ));
    inMemoryTableManager.recoverTables(tables);

    List<FileAccessInfo> expectedFiles = Arrays.asList(
        new FileAccessInfo(1, TEST_FILES.get(1), 4,
            ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(2, TEST_FILES.get(2), 3,
            ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(3, TEST_FILES.get(3), 3,
            ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(4, TEST_FILES.get(4), 2,
            ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(5, TEST_FILES.get(5), 2,
            ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    );
    List<FileAccessInfo> hotFiles =
        accessCountTableManager.search(FileAccessInfoSearchRequest.builder()
            .lastAccessedTime(TimeInterval.builder()
                .from(Instant.ofEpochMilli(55 * ONE_SECOND_IN_MILLIS))
                .to(Instant.ofEpochMilli(ONE_MINUTE_IN_MILLIS + 56 * ONE_SECOND_IN_MILLIS))
                .build())
            .build());
    assertEquals(expectedFiles, hotFiles);
  }

  @Test
  public void testGetHotFilesWhenIntervalStartTimeIncludesIntoChildTable()
      throws MetaStoreException {
    /*
                     |--interval-|
       |-s-| |-s-| |-s-|
    |--------min-------------------|
    */
    createTestFiles();
    DbAccessCountTableManager tableManager = accessCountTableManager.getDbTableManager();
    AccessCountTable t4 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 35 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 40 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t5 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 45 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 50 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t6 = new AccessCountTable(ONE_MINUTE_IN_MILLIS, 2 * ONE_MINUTE_IN_MILLIS);
    List<AccessCountTable> tables = Arrays.asList(t4, t5, t6);
    tables.forEach(t -> {
      try {
        tableManager.createTable(t);
      } catch (MetaStoreException e) {
        throw new RuntimeException(e);
      }
    });
    tableManager.handleAggregatedEvents(t4, Arrays.asList(
        new AggregatedAccessCounts(5, 1, ONE_MINUTE_IN_MILLIS + 38 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t5, Arrays.asList(
        new AggregatedAccessCounts(1, 4, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 3, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 2, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    ));
    tableManager.handleAggregatedEvents(t6, Arrays.asList(
        new AggregatedAccessCounts(1, 4, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 3, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 3, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    ));
    inMemoryTableManager.recoverTables(tables);

    List<FileAccessInfo> expectedFiles = Arrays.asList(
        new FileAccessInfo(1, TEST_FILES.get(1), 2,
            ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(2, TEST_FILES.get(2), 1,
            ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(3, TEST_FILES.get(3), 1,
            ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(4, TEST_FILES.get(4), 1,
            ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS)
    );

    List<FileAccessInfo> hotFiles =
        accessCountTableManager.search(FileAccessInfoSearchRequest.builder()
            .lastAccessedTime(TimeInterval.builder()
                .from(Instant.ofEpochMilli(ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS))
                .to(Instant.ofEpochMilli(ONE_MINUTE_IN_MILLIS + 56 * ONE_SECOND_IN_MILLIS))
                .build())
            .build());
    assertEquals(expectedFiles, hotFiles);
  }

  @Test
  public void testGetHotFilesWhenIntervalStartAndEndTimeIncludesIntoChildTables()
      throws MetaStoreException {
    /*
         |--interval-|
       |-s-| |-s-| |-s-|
    |--------min-----------|
    */
    createTestFiles();
    DbAccessCountTableManager tableManager = accessCountTableManager.getDbTableManager();
    AccessCountTable t1 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 5 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t2 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 20 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 25 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t4 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 35 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 40 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t5 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 45 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 50 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t6 = new AccessCountTable(ONE_MINUTE_IN_MILLIS, 2 * ONE_MINUTE_IN_MILLIS);
    List<AccessCountTable> tables = Arrays.asList(t1, t2, t4, t5, t6);
    tables.forEach(t -> {
      try {
        tableManager.createTable(t);
      } catch (MetaStoreException e) {
        throw new RuntimeException(e);
      }
    });
    tableManager.handleAggregatedEvents(t1, Arrays.asList(
        new AggregatedAccessCounts(1, 4, ONE_MINUTE_IN_MILLIS + 9 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 2, ONE_MINUTE_IN_MILLIS + 8 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 1, ONE_MINUTE_IN_MILLIS + 5 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 2, ONE_MINUTE_IN_MILLIS + 9 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 1, ONE_MINUTE_IN_MILLIS + 7 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t2, Arrays.asList(
        new AggregatedAccessCounts(2, 1, ONE_MINUTE_IN_MILLIS + 21 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 1, ONE_MINUTE_IN_MILLIS + 21 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t4, Arrays.asList(
        new AggregatedAccessCounts(5, 1, ONE_MINUTE_IN_MILLIS + 38 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t5, Arrays.asList(
        new AggregatedAccessCounts(1, 4, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 3, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 2, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    ));
    tableManager.handleAggregatedEvents(t6, Arrays.asList(
        new AggregatedAccessCounts(1, 4, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 3, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 3, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    ));
    inMemoryTableManager.recoverTables(tables);

    List<FileAccessInfo> expectedFiles = Arrays.asList(
        new FileAccessInfo(1, TEST_FILES.get(1), 4,
            ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(2, TEST_FILES.get(2), 2,
            ONE_MINUTE_IN_MILLIS + 21 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(3, TEST_FILES.get(3), 2,
            ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(4, TEST_FILES.get(4), 2,
            ONE_MINUTE_IN_MILLIS + 21 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(5, TEST_FILES.get(5), 2,
            ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    );

    List<FileAccessInfo> hotFiles =
        accessCountTableManager.search(FileAccessInfoSearchRequest.builder()
            .lastAccessedTime(TimeInterval.builder()
                .from(Instant.ofEpochMilli(ONE_MINUTE_IN_MILLIS + 8 * ONE_SECOND_IN_MILLIS))
                .to(Instant.ofEpochMilli(ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS))
                .build())
            .build());
    assertEquals(expectedFiles, hotFiles);
  }

  @Test
  public void testGetHotFilesWhenIntervalBiggerThanExistedTablesCombineGranularity()
      throws MetaStoreException {
    /*
    |---------interval------------------------|
                          |-s-| |-s-| |-s-|
    |-----min-----------|-------------------|
    */
    createTestFiles();
    DbAccessCountTableManager tableManager = accessCountTableManager.getDbTableManager();

    AccessCountTable t0 = new AccessCountTable(0, ONE_MINUTE_IN_MILLIS);
    AccessCountTable t1 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 5 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t2 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 20 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 25 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t4 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 35 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 40 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t5 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 45 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 50 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t6 = new AccessCountTable(ONE_MINUTE_IN_MILLIS, 2 * ONE_MINUTE_IN_MILLIS);
    List<AccessCountTable> tables = Arrays.asList(t0, t1, t2, t4, t5, t6);
    tables.forEach(t -> {
      try {
        tableManager.createTable(t);
      } catch (MetaStoreException e) {
        throw new RuntimeException(e);
      }
    });
    tableManager.handleAggregatedEvents(t0, Arrays.asList(
        new AggregatedAccessCounts(1, 2, 38 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 5, 44 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 1, 45 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 2, 51 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t1, Arrays.asList(
        new AggregatedAccessCounts(1, 4, ONE_MINUTE_IN_MILLIS + 9 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 2, ONE_MINUTE_IN_MILLIS + 8 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 1, ONE_MINUTE_IN_MILLIS + 5 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 2, ONE_MINUTE_IN_MILLIS + 9 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 1, ONE_MINUTE_IN_MILLIS + 7 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t2, Arrays.asList(
        new AggregatedAccessCounts(2, 1, ONE_MINUTE_IN_MILLIS + 21 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 1, ONE_MINUTE_IN_MILLIS + 21 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t4, Arrays.asList(
        new AggregatedAccessCounts(5, 1, ONE_MINUTE_IN_MILLIS + 38 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t5, Arrays.asList(
        new AggregatedAccessCounts(1, 4, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 3, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 2, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    ));
    tableManager.handleAggregatedEvents(t6, Arrays.asList(
        new AggregatedAccessCounts(1, 4, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 3, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 3, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    ));
    inMemoryTableManager.recoverTables(tables);

    List<FileAccessInfo> expectedFiles = Arrays.asList(
        new FileAccessInfo(1, TEST_FILES.get(1), 6,
            ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(2, TEST_FILES.get(2), 3,
            ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(3, TEST_FILES.get(3), 8,
            ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(4, TEST_FILES.get(4), 4,
            ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(5, TEST_FILES.get(5), 5,
            ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    );

    List<FileAccessInfo> hotFiles =
        accessCountTableManager.search(FileAccessInfoSearchRequest.builder()
            .lastAccessedTime(TimeInterval.builder()
                .from(Instant.ofEpochMilli(0))
                .to(Instant.ofEpochMilli(2 * ONE_MINUTE_IN_MILLIS + 4 * ONE_SECOND_IN_MILLIS))
                .build())
            .build());
    assertEquals(expectedFiles, hotFiles);
  }

  @Test
  public void testGetHotFilesWhenIntervalEndsWithinSmallestTableCombinedGranularity()
      throws MetaStoreException {
    /*
    |---------interval------------|
                          |-s-| |-s-|
    |-----min----------|--------------|
    |-----------------hour--------...-----|
    */
    createTestFiles();
    DbAccessCountTableManager tableManager = accessCountTableManager.getDbTableManager();
    AccessCountTable t0 = new AccessCountTable(0, ONE_MINUTE_IN_MILLIS);
    AccessCountTable t1 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 5 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t2 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 20 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 25 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t4 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 35 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 40 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t5 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 45 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 50 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t6 = new AccessCountTable(ONE_MINUTE_IN_MILLIS, 2 * ONE_MINUTE_IN_MILLIS);
    AccessCountTable t7 = new AccessCountTable(0, ONE_HOUR_IN_MILLIS);
    List<AccessCountTable> tables = Arrays.asList(t0, t1, t2, t4, t5, t6, t7);
    tables.forEach(t -> {
      try {
        tableManager.createTable(t);
      } catch (MetaStoreException e) {
        throw new RuntimeException(e);
      }
    });
    tableManager.handleAggregatedEvents(t0, Arrays.asList(
        new AggregatedAccessCounts(1, 2, 38 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 5, 44 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 1, 45 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 2, 51 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t1, Arrays.asList(
        new AggregatedAccessCounts(1, 4, ONE_MINUTE_IN_MILLIS + 9 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 2, ONE_MINUTE_IN_MILLIS + 8 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 1, ONE_MINUTE_IN_MILLIS + 5 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 2, ONE_MINUTE_IN_MILLIS + 9 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 1, ONE_MINUTE_IN_MILLIS + 7 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t2, Arrays.asList(
        new AggregatedAccessCounts(2, 1, ONE_MINUTE_IN_MILLIS + 21 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 1, ONE_MINUTE_IN_MILLIS + 21 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t4, Arrays.asList(
        new AggregatedAccessCounts(5, 1, ONE_MINUTE_IN_MILLIS + 38 * ONE_SECOND_IN_MILLIS)));
    tableManager.handleAggregatedEvents(t5, Arrays.asList(
        new AggregatedAccessCounts(1, 4, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 3, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 2, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    ));
    tableManager.handleAggregatedEvents(t6, Arrays.asList(
        new AggregatedAccessCounts(1, 4, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 3, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 3, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    ));
    tableManager.handleAggregatedEvents(t7, Arrays.asList(
        new AggregatedAccessCounts(1, 24, 50 * ONE_MINUTE_IN_MILLIS),
        new AggregatedAccessCounts(2, 18, 49 * ONE_MINUTE_IN_MILLIS),
        new AggregatedAccessCounts(3, 18, 30 * ONE_MINUTE_IN_MILLIS),
        new AggregatedAccessCounts(4, 15, 55 * ONE_MINUTE_IN_MILLIS),
        new AggregatedAccessCounts(5, 27, 57 * ONE_MINUTE_IN_MILLIS)
    ));
    inMemoryTableManager.recoverTables(tables);

    List<FileAccessInfo> expectedFiles = Arrays.asList(
        new FileAccessInfo(1, TEST_FILES.get(1), 8,
            ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(2, TEST_FILES.get(2), 3,
            ONE_MINUTE_IN_MILLIS + 21 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(3, TEST_FILES.get(3), 8,
            ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(4, TEST_FILES.get(4), 4,
            ONE_MINUTE_IN_MILLIS + 21 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(5, TEST_FILES.get(5), 5,
            ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    );

    List<FileAccessInfo> hotFiles =
        accessCountTableManager.search(FileAccessInfoSearchRequest.builder()
            .lastAccessedTime(TimeInterval.builder()
                .from(Instant.ofEpochMilli(0))
                .to(Instant.ofEpochMilli(ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS))
                .build())
            .build());
    assertEquals(expectedFiles, hotFiles);
  }

  @Test
  public void testGetHotFilesWhenIntervalStartsInParentTableAndEndsInChildTable()
      throws MetaStoreException {
    /*
        |---interval--|
                    |-s-|
    |---------m------------|
     */
    createTestFiles();
    DbAccessCountTableManager tableManager = accessCountTableManager.getDbTableManager();

    AccessCountTable t5 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 45 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 50 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t6 = new AccessCountTable(ONE_MINUTE_IN_MILLIS, 2 * ONE_MINUTE_IN_MILLIS);
    List<AccessCountTable> tables = Arrays.asList(t5, t6);
    tables.forEach(t -> {
      try {
        tableManager.createTable(t);
      } catch (MetaStoreException e) {
        throw new RuntimeException(e);
      }
    });
    tableManager.handleAggregatedEvents(t5, Arrays.asList(
        new AggregatedAccessCounts(1, 4, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 3, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 2, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    ));
    tableManager.handleAggregatedEvents(t6, Arrays.asList(
        new AggregatedAccessCounts(1, 10, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 5, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 7, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 8, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 4, ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    ));
    inMemoryTableManager.recoverTables(tables);

    List<FileAccessInfo> expectedFiles = Arrays.asList(
        new FileAccessInfo(1, TEST_FILES.get(1), 2,
            ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(3, TEST_FILES.get(3), 2,
            ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(5, TEST_FILES.get(5), 1,
            ONE_MINUTE_IN_MILLIS + 46 * ONE_SECOND_IN_MILLIS)
    );

    List<FileAccessInfo> hotFiles =
        accessCountTableManager.search(FileAccessInfoSearchRequest.builder()
            .lastAccessedTime(TimeInterval.builder()
                .from(Instant.ofEpochMilli(ONE_MINUTE_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS))
                .to(Instant.ofEpochMilli(ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS))
                .build())
            .build());
    assertEquals(expectedFiles, hotFiles);
  }

  @Test
  public void testGetHotFilesWhenIntervalIncludesOnlyInParentTable()
      throws MetaStoreException {
    /*
       |--interval--|
                      |-s-|
    |---------m------------|
     */
    createTestFiles();
    DbAccessCountTableManager tableManager = accessCountTableManager.getDbTableManager();

    AccessCountTable t5 = new AccessCountTable(ONE_MINUTE_IN_MILLIS + 45 * ONE_SECOND_IN_MILLIS,
        ONE_MINUTE_IN_MILLIS + 50 * ONE_SECOND_IN_MILLIS);
    AccessCountTable t6 = new AccessCountTable(ONE_MINUTE_IN_MILLIS, 2 * ONE_MINUTE_IN_MILLIS);
    List<AccessCountTable> tables = Arrays.asList(t5, t6);
    tables.forEach(t -> {
      try {
        tableManager.createTable(t);
      } catch (MetaStoreException e) {
        throw new RuntimeException(e);
      }
    });
    tableManager.handleAggregatedEvents(t5, Arrays.asList(
        new AggregatedAccessCounts(1, 4, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 3, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 3, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS)
    ));
    tableManager.handleAggregatedEvents(t6, Arrays.asList(
        new AggregatedAccessCounts(1, 10, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(2, 15, ONE_MINUTE_IN_MILLIS + 20 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(3, 7, ONE_MINUTE_IN_MILLIS + 48 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(4, 8, ONE_MINUTE_IN_MILLIS + 49 * ONE_SECOND_IN_MILLIS),
        new AggregatedAccessCounts(5, 4, ONE_MINUTE_IN_MILLIS + 30 * ONE_SECOND_IN_MILLIS)
    ));
    inMemoryTableManager.recoverTables(tables);

    List<FileAccessInfo> expectedFiles = Arrays.asList(
        new FileAccessInfo(2, TEST_FILES.get(2), 8,
            ONE_MINUTE_IN_MILLIS + 20 * ONE_SECOND_IN_MILLIS),
        new FileAccessInfo(5, TEST_FILES.get(5), 2,
            ONE_MINUTE_IN_MILLIS + 30 * ONE_SECOND_IN_MILLIS)
    );

    List<FileAccessInfo> hotFiles =
        accessCountTableManager.search(FileAccessInfoSearchRequest.builder()
            .lastAccessedTime(TimeInterval.builder()
                .from(Instant.ofEpochMilli(ONE_MINUTE_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS))
                .to(Instant.ofEpochMilli(ONE_MINUTE_IN_MILLIS + 40 * ONE_SECOND_IN_MILLIS))
                .build())
            .build());
    assertEquals(expectedFiles, hotFiles);
  }

  private void submitAccessEvents() {
    InMemoryAccessEventAggregator accessEventAggregator =
        accessCountTableManager.getAccessEventAggregator();
    List<FileAccessEvent> accessEvents = Arrays.asList(
        new FileAccessEvent(TEST_FILES.get(0), 0),
        new FileAccessEvent(TEST_FILES.get(1), 1),
        new FileAccessEvent(TEST_FILES.get(2),
            2 * ONE_MINUTE_IN_MILLIS + 1),
        new FileAccessEvent("/unknown",
            3 * ONE_MINUTE_IN_MILLIS),
        new FileAccessEvent(TEST_FILES.get(1),
            4 * ONE_MINUTE_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS),
        new FileAccessEvent(TEST_FILES.get(2),
            ONE_HOUR_IN_MILLIS + 5 * ONE_MINUTE_IN_MILLIS),
        new FileAccessEvent(TEST_FILES.get(3),
            ONE_HOUR_IN_MILLIS + 9 * ONE_MINUTE_IN_MILLIS),
        new FileAccessEvent(TEST_FILES.get(3),
            8 * ONE_HOUR_IN_MILLIS),
        new FileAccessEvent(TEST_FILES.get(3),
            ONE_DAY_IN_MILLIS + 12 * ONE_HOUR_IN_MILLIS),
        new FileAccessEvent(TEST_FILES.get(2),
            ONE_DAY_IN_MILLIS + 12 * ONE_HOUR_IN_MILLIS + 1),
        new FileAccessEvent(TEST_FILES.get(1),
            ONE_DAY_IN_MILLIS + 13 * ONE_HOUR_IN_MILLIS + 10 * ONE_SECOND_IN_MILLIS),
        new FileAccessEvent(TEST_FILES.get(4),
            ONE_DAY_IN_MILLIS + 17 * ONE_HOUR_IN_MILLIS),
        new FileAccessEvent(TEST_FILES.get(5),
            ONE_DAY_IN_MILLIS + 18 * ONE_HOUR_IN_MILLIS + 10),
        new FileAccessEvent(TEST_FILES.get(3),
            ONE_DAY_IN_MILLIS + 23 * ONE_HOUR_IN_MILLIS + 59 * ONE_MINUTE_IN_MILLIS
                + 58 * ONE_SECOND_IN_MILLIS),
        new FileAccessEvent(TEST_FILES.get(3),
            ONE_DAY_IN_MILLIS + 23 * ONE_HOUR_IN_MILLIS + 59 * ONE_MINUTE_IN_MILLIS
                + 59 * ONE_SECOND_IN_MILLIS),
        new FileAccessEvent("", 2 * ONE_DAY_IN_MILLIS)
    );
    accessEventAggregator.aggregate(accessEvents);
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
