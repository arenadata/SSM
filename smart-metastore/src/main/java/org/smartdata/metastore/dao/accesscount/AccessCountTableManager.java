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

import lombok.Getter;
import org.apache.hadoop.conf.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.dao.Searchable;
import org.smartdata.metastore.model.AccessCountTable;
import org.smartdata.metastore.model.AggregatedAccessCounts;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.FileAccessInfoSortField;
import org.smartdata.metastore.transaction.TransactionRunner;
import org.smartdata.metastore.utils.TimeGranularity;
import org.smartdata.model.FileAccessInfo;
import org.smartdata.model.TimeInterval;
import org.smartdata.model.request.FileAccessInfoSearchRequest;
import org.smartdata.utils.DateTimeUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.stream.Collectors;

import static org.smartdata.conf.SmartConfKeys.SMART_ACCESS_COUNT_AGGREGATION_INTERVAL_MS;
import static org.smartdata.conf.SmartConfKeys.SMART_ACCESS_COUNT_AGGREGATION_INTERVAL_MS_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_ACCESS_COUNT_AGGREGATOR_FAILOVER_KEY;
import static org.smartdata.metastore.utils.TimeGranularity.decreaseGranularity;
import static org.smartdata.metastore.utils.TimeGranularity.increaseGranularity;
import static org.springframework.transaction.annotation.Isolation.SERIALIZABLE;

@Getter
public class AccessCountTableManager implements
    Searchable<FileAccessInfoSearchRequest, FileAccessInfo, FileAccessInfoSortField> {
  private final InMemoryAccessEventAggregator accessEventAggregator;
  private final InMemoryAccessCountTableManager inMemoryTableManager;
  private final DbAccessCountTableManager dbTableManager;
  private final TransactionRunner transactionRunner;
  private final int defaultHotFilesLimit;

  public static final Logger LOG =
      LoggerFactory.getLogger(AccessCountTableManager.class);

  public AccessCountTableManager(MetaStore metaStore,
                                 ExecutorService service,
                                 Configuration configuration) {
    int aggregationIntervalMs = configuration.getInt(
        SMART_ACCESS_COUNT_AGGREGATION_INTERVAL_MS,
        SMART_ACCESS_COUNT_AGGREGATION_INTERVAL_MS_DEFAULT);
    AccessCountEventAggregatorFailover.Strategy eventAggregatorFailoverStrategy =
        configuration.getEnum(SMART_ACCESS_COUNT_AGGREGATOR_FAILOVER_KEY,
            AccessCountEventAggregatorFailover.Strategy.SUBMIT_NEW_FAILED_EVENTS_LATER);

    this.accessEventAggregator = new InMemoryAccessEventAggregator(
        metaStore.fileInfoDao(),
        this::onAggregationWindowFinish,
        AccessCountEventAggregatorFailover.of(eventAggregatorFailoverStrategy),
        aggregationIntervalMs);

    this.transactionRunner = new TransactionRunner(metaStore.transactionManager());
    transactionRunner.setIsolationLevel(SERIALIZABLE);

    this.dbTableManager = new DbAccessCountTableManager(
        metaStore.getDataSource(),
        transactionRunner,
        metaStore.accessCountTableDao(),
        metaStore.accessCountEventDao(),
        metaStore.cacheFileDao());
    this.inMemoryTableManager = new InMemoryAccessCountTableManager(
        dbTableManager, service, configuration);
    this.defaultHotFilesLimit = configuration.getInt(
        SmartConfKeys.SMART_TOP_HOT_FILES_NUM_KEY,
        SmartConfKeys.SMART_TOP_HOT_FILES_NUM_DEFAULT);

    recoverTables();
  }

  public List<AccessCountTable> getTablesForLast(long intervalMillis) throws MetaStoreException {
    Deque<AccessCountTable> secondDeque =
        inMemoryTableManager.getTablesOfGranularity(TimeGranularity.SECOND);
    if (secondDeque.isEmpty()) {
      return Collections.emptyList();
    }

    long endTime = secondDeque.getLast().getEndTime();
    return getAccessCountTables(endTime - intervalMillis, endTime);
  }

  public void createTable(AccessCountTable table) throws MetaStoreException {
    try {
      transactionRunner.inTransaction(() -> {
        dbTableManager.createTable(table);
        inMemoryTableManager.addTable(table);
      });
    } catch (MetaStoreException exception) {
      LOG.error("Error creating access count table {}", table, exception);
      throw exception;
    }
  }

  private void onAggregationWindowFinish(
      long windowStart,
      long windowEnd,
      Collection<AggregatedAccessCounts> aggregatedAccessCounts) {
    if (aggregatedAccessCounts.isEmpty()) {
      return;
    }

    AccessCountTable table = new AccessCountTable(windowStart, windowEnd);
    try {
      transactionRunner.inTransaction(() -> {
        createTable(table);
        dbTableManager.handleAggregatedEvents(table, aggregatedAccessCounts);
      });
    } catch (MetaStoreException exception) {
      LOG.error("Error creating access count table {}", table, exception);
      throw new RuntimeException(exception);
    }
  }

  private void recoverTables() {
    try {
      transactionRunner.inTransaction(() -> {
        List<AccessCountTable> tables = dbTableManager.getTables();
        inMemoryTableManager.recoverTables(tables);
      });
    } catch (MetaStoreException exception) {
      LOG.error("Error recovering existing access count tables", exception);
    }
  }

  /**
   * Getting access count tables by interval:
   * 1. found base granularity by searching interval, if tables are not exist, increase granularity
   * 2. get access count tables by base granularity with startTime less or equals searching endTime
   * 3. Filter tables by starTime less or equals searching endTime.
   * 4. Filter tables by endTime > searching startTime and if parentTable != null,
   * also filter by endTime <= parentTable.endTime. It is needed because we are getting
   * all tables of some granularity.
   * 5. For all found tables from the list we should add corresponding tables to the result
   * according to their intervals and search granularity. For non-second granularity we get child
   * tables recursively. If we have case when one of the searching border (startTime or endTime)
   * bigger (less) than table startTime (endTime), we have to create partial table, which is based
   * on current table (in some cases we create partial table base on parentTable,
   * when prentTable != null and there are no tables of small granularity between
   * parentTable.startTime and table.startTime or between searching startTime and
   * parentTable.endTime). Add corresponding tables to the result and update searching startTime and
   * 6. Decrease searching granularity and update it, check that searching
   * startTime = endTime, if no, repeat from p.2
   *
   * @param startTime start time of the search interval
   * @param endTime   end time of the search interval
   * @return List of access count tables
   * @throws MetaStoreException error
   */
  private List<AccessCountTable> getAccessCountTables(long startTime,
                                                      long endTime) throws MetaStoreException {
    final TimeGranularity startGranularity = TimeGranularity.of(endTime - startTime);
    TimeGranularity searchIntervalGranularity = startGranularity;
    Collection<AccessCountTable> tables = inMemoryTableManager.getTablesOfGranularity(
            searchIntervalGranularity).stream()
        .filter(t -> t.getStartTime() <= endTime)
        .collect(Collectors.toList());
    boolean foundTables = !tables.isEmpty();
    while (!foundTables) {
      searchIntervalGranularity = increaseGranularity(searchIntervalGranularity);
      if (searchIntervalGranularity == null) {
        searchIntervalGranularity = startGranularity;
        foundTables = true;
      } else {
        tables = inMemoryTableManager.getTablesOfGranularity(
            searchIntervalGranularity);
        Long accessCountTableStartTime = tables.stream()
            .findFirst()
            .map(AccessCountTable::getStartTime)
            .orElse(Long.MAX_VALUE);
        foundTables = accessCountTableStartTime <= startTime;
      }
    }
    return getAccessCountTables(startTime, endTime, null, searchIntervalGranularity);
  }

  private List<AccessCountTable> getAccessCountTables(long startTime,
                                                      long endTime,
                                                      AccessCountTable parentTable,
                                                      TimeGranularity baseGranularity)
      throws MetaStoreException {
    final TimeGranularity startGranularity = TimeGranularity.of(endTime - startTime);
    final List<AccessCountTable> result = new ArrayList<>();
    TimeGranularity searchIntervalGranularity;
    if (baseGranularity != null) {
      searchIntervalGranularity = baseGranularity;
    } else {
      searchIntervalGranularity = startGranularity;
    }
    do {
      long finalStartTime = startTime;
      Collection<AccessCountTable> tables = inMemoryTableManager.getTablesOfGranularity(
              searchIntervalGranularity).stream()
          .filter(t -> t.getStartTime() <= endTime)
          .filter(t -> {
            if (parentTable != null) {
              //include child tables which has endTime after startTime
              // and includes into parent table
              return t.getEndTime() > finalStartTime && t.getEndTime() <= parentTable.getEndTime();
            }
            return t.getEndTime() > finalStartTime;
          })
          .collect(Collectors.toList());
      int n = 0;
      for (AccessCountTable table : tables) {
        n++;
        //skip tables if it starts after specified startTime
        if (table.getStartTime() > endTime) {
          continue;
        }
        if (table.getStartTime() <= startTime) {
          if (table.getStartTime() == startTime) {
            if (table.getEndTime() <= endTime) {
              result.add(table);
              startTime = table.getEndTime();
            } else {
              //table.endTime > endTime
              result.addAll(getChildOrCreatePartialTables(searchIntervalGranularity,
                  table, startTime, endTime));
              startTime = endTime;
            }
          } else {
            if (table.getEndTime() <= endTime) {
              result.addAll(getChildOrCreatePartialTables(searchIntervalGranularity,
                  table, startTime, table.getEndTime()));
              startTime = table.getEndTime();
            } else {
              result.addAll(getChildOrCreatePartialTables(searchIntervalGranularity,
                  table, startTime, endTime));
              startTime = endTime;
            }
          }
          continue;
        }
        //table.startTime > startTime
        if (table.getEndTime() <= endTime) {
          //if table is child and the first, we have to create partial table for this interval
          if (parentTable != null && n <= 1) {
            //create partial table based on parent table from startTime to table.startTime
            addPartialTable(parentTable, startTime, table.getStartTime())
                .ifPresent(result::add);
          }
          result.add(table);
          startTime = table.getEndTime();
        } else {
          addPartialTable(table, table.getStartTime(), endTime)
              .ifPresent(result::add);
          startTime = endTime;
        }
      }
      searchIntervalGranularity = decreaseGranularity(searchIntervalGranularity);
      if (searchIntervalGranularity == null && startTime != endTime) {
        if (parentTable != null) {
          //create partial table based on parent table from startTime to endTime
          addPartialTable(parentTable, startTime, endTime)
              .ifPresent(result::add);
        }
        startTime = endTime;
      }
    } while (startTime != endTime);
    return result;
  }

  private List<AccessCountTable> getChildOrCreatePartialTables(
      TimeGranularity searchIntervalGranularity,
      AccessCountTable table,
      long startTime,
      long endTime)
      throws MetaStoreException {
    if (searchIntervalGranularity != TimeGranularity.SECOND) {
      return getAccessCountTables(startTime, endTime, table, null);
    } else {
      return addPartialTable(table, startTime, endTime)
          .map(Collections::singletonList)
          .orElse(Collections.emptyList());
    }
  }

  private Optional<AccessCountTable> addPartialTable(AccessCountTable sourceTable,
                                                     long startTime,
                                                     long endTime) throws MetaStoreException {
    // The access count table interval intersects with the search interval
    if (!inMemoryTableManager.tableExists(startTime, endTime)) {
      // Create ephemeral table with file access events whose last access time
      // is greater than or equal to the startTime. We also assume that file accesses
      // occurred evenly over time, so we can simply divide the number of file accesses
      // during the table interval by the ratio of the search interval and the table interval
      AccessCountTable partialTable =
          new AccessCountTable(startTime, endTime, true);
      dbTableManager.createPartialTable(partialTable, sourceTable);
      return Optional.of(partialTable);
    } else {
      return Optional.empty();
    }
  }

  @Override
  public SearchResult<FileAccessInfo> search(FileAccessInfoSearchRequest searchRequest,
                                             PageRequest<FileAccessInfoSortField> pageRequest) {
    try {
      return transactionRunner.inTransaction(() -> {
        Set<String> tables = getAccessCountTables(searchRequest.getLastAccessedTime());
        if (tables.isEmpty()) {
          return SearchResult.of(Collections.emptyList(), 0);
        }
        return dbTableManager.getFileAccessInfoList(searchRequest.withAccessCountTables(tables),
            pageRequest);
      });
    } catch (MetaStoreException e) {
      LOG.error("Failed to get file access count information with pagination", e);
      throw new RuntimeException(e);
    }
  }

  @Override
  public List<FileAccessInfo> search(FileAccessInfoSearchRequest searchRequest) {
    try {
      return transactionRunner.inTransaction(() -> {
        Set<String> tables = getAccessCountTables(searchRequest.getLastAccessedTime());
        if (tables.isEmpty()) {
          return Collections.emptyList();
        }
        return dbTableManager.getFileAccessInfoList(searchRequest.withAccessCountTables(tables));
      });
    } catch (MetaStoreException e) {
      LOG.error("Failed to get file access count information", e);
      throw new RuntimeException(e);
    }
  }

  private Set<String> getAccessCountTables(TimeInterval timeInterval) throws MetaStoreException {
    long startTime = Optional.ofNullable(DateTimeUtils.intervalStartToEpoch(timeInterval))
        .orElse(0L);
    long endTime = Optional.ofNullable(DateTimeUtils.intervalEndToEpoch(timeInterval))
        .orElse(System.currentTimeMillis());
    return getAccessCountTables(startTime, endTime).stream()
        .map(AccessCountTable::getTableName)
        .collect(Collectors.toSet());
  }
}
