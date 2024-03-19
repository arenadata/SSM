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

import com.google.common.annotations.VisibleForTesting;
import org.apache.hadoop.conf.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.utils.TimeGranularity;
import org.smartdata.metastore.utils.TimeUtils;
import org.smartdata.metrics.FileAccessEvent;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.smartdata.conf.SmartConfKeys.SMART_ACCESS_COUNT_AGGREGATION_INTERVAL_MS;
import static org.smartdata.conf.SmartConfKeys.SMART_ACCESS_COUNT_AGGREGATION_INTERVAL_MS_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_NUM_DAY_TABLES_TO_KEEP_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_NUM_DAY_TABLES_TO_KEEP_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_NUM_HOUR_TABLES_TO_KEEP_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_NUM_HOUR_TABLES_TO_KEEP_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_NUM_HOUR_TABLES_TO_KEEP_MIN;
import static org.smartdata.conf.SmartConfKeys.SMART_NUM_MINUTE_TABLES_TO_KEEP_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_NUM_MINUTE_TABLES_TO_KEEP_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_NUM_MINUTE_TABLES_TO_KEEP_MIN;
import static org.smartdata.conf.SmartConfKeys.SMART_NUM_SECOND_TABLES_TO_KEEP_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_NUM_SECOND_TABLES_TO_KEEP_KEY;
import static org.smartdata.metastore.utils.Constants.ONE_MINUTE_IN_MILLIS;

public class AccessCountTableManager {
  private final MetaStore metaStore;
  private final Map<TimeGranularity, AccessCountTableDeque> tableDeques;
  private final AccessEventAggregator accessEventAggregator;
  private final ExecutorService executorService;
  private final Configuration configuration;
  private AccessCountTableDeque secondTableDeque;

  public static final Logger LOG =
      LoggerFactory.getLogger(AccessCountTableManager.class);

  public AccessCountTableManager(MetaStore adapter) {
    this(adapter, Executors.newFixedThreadPool(4), new Configuration());
  }

  public AccessCountTableManager(MetaStore adapter,
      ExecutorService service, Configuration configuration) {
    this.metaStore = adapter;
    this.tableDeques = new HashMap<>();
    this.executorService = service;
    this.configuration = configuration;

    int aggregationIntervalMs = configuration.getInt(
        SMART_ACCESS_COUNT_AGGREGATION_INTERVAL_MS,
        SMART_ACCESS_COUNT_AGGREGATION_INTERVAL_MS_DEFAULT);
    this.accessEventAggregator = new AccessEventAggregator(adapter, this, aggregationIntervalMs);

    initTables();
  }

  private int getAccessTablesCount(String configKey, int defaultValue, int minimalCount) {
    int tableCount = configuration.getInt(configKey, defaultValue);

    if (tableCount < minimalCount) {
      String errorMessage = String.format(
          "Wrong value for option %s. It should be at least %d", configKey, minimalCount);
      LOG.error(errorMessage);
      throw new IllegalArgumentException(errorMessage);
    }
    return tableCount;
  }

  private void initTables() {
    AccessCountTableAggregator aggregator = new AccessCountTableAggregator(metaStore);

    int perDayAccessTablesCount = configuration.getInt(SMART_NUM_DAY_TABLES_TO_KEEP_KEY,
        SMART_NUM_DAY_TABLES_TO_KEEP_DEFAULT);
    AccessCountTableDeque dayTableDeque = new AccessCountTableDeque(
        new CountEvictor(metaStore, perDayAccessTablesCount));
    TableAddOpListener dayTableListener =
        TableAddOpListener.perDay(dayTableDeque, aggregator, executorService);

    int perHourAccessTablesCount = getAccessTablesCount(
        SMART_NUM_HOUR_TABLES_TO_KEEP_KEY,
        SMART_NUM_HOUR_TABLES_TO_KEEP_DEFAULT,
        SMART_NUM_HOUR_TABLES_TO_KEEP_MIN);
    AccessCountTableDeque hourTableDeque = new AccessCountTableDeque(
        new CountEvictor(metaStore, perHourAccessTablesCount), dayTableListener);
    TableAddOpListener hourTableListener =
        TableAddOpListener.perHour(hourTableDeque, aggregator, executorService);

    int perMinuteAccessTablesCount = getAccessTablesCount(
        SMART_NUM_MINUTE_TABLES_TO_KEEP_KEY,
        SMART_NUM_MINUTE_TABLES_TO_KEEP_DEFAULT,
        SMART_NUM_MINUTE_TABLES_TO_KEEP_MIN);
    AccessCountTableDeque minuteTableDeque = new AccessCountTableDeque(
        new CountEvictor(metaStore, perMinuteAccessTablesCount), hourTableListener);
    TableAddOpListener minuteTableListener =
        TableAddOpListener.perMinute(minuteTableDeque, aggregator,
            executorService);

    int minimalSecondAccessTablesCount =
        (int) (ONE_MINUTE_IN_MILLIS / accessEventAggregator.getAggregationGranularity());

    int perSecondAccessTablesCount = getAccessTablesCount(
        SMART_NUM_SECOND_TABLES_TO_KEEP_KEY,
        SMART_NUM_SECOND_TABLES_TO_KEEP_DEFAULT,
        minimalSecondAccessTablesCount);
    this.secondTableDeque = new AccessCountTableDeque(
            new CountEvictor(metaStore, perSecondAccessTablesCount), minuteTableListener);

    tableDeques.put(TimeGranularity.SECOND, secondTableDeque);
    tableDeques.put(TimeGranularity.MINUTE, minuteTableDeque);
    tableDeques.put(TimeGranularity.HOUR, hourTableDeque);
    tableDeques.put(TimeGranularity.DAY, dayTableDeque);
    recoverTables();
  }

  private void recoverTables() {
    try {
      List<AccessCountTable> tables = metaStore.getAllSortedTables();

      if (tables.isEmpty()) {
        LOG.info("No existing access count tables to recover.");
        return;
      }

      LOG.info("Loading existing access count tables: {}", tables);
      for (AccessCountTable table : tables) {
        if (tableDeques.containsKey(table.getGranularity())) {
          tableDeques.get(table.getGranularity()).add(table);
        }
      }

      // aggregate old tables if needed
      AccessCountTable lastOldTable = tables.get(tables.size() - 1);
      Optional.ofNullable(tableDeques.get(lastOldTable.getGranularity()))
          .ifPresent(deque -> deque.notifyListener(lastOldTable));

      LOG.info("Existing access count tables were successfully loaded");
    } catch (MetaStoreException e) {
      LOG.error("Error during recovering access count tables", e);
    }
  }

  public void addTable(AccessCountTable accessCountTable) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(accessCountTable.toString());
    }
    secondTableDeque.addAndNotifyListener(accessCountTable);
  }

  public void onAccessEventsArrived(List<FileAccessEvent> accessEvents) {
    accessEventAggregator.addAccessEvents(accessEvents);
  }

  public List<AccessCountTable> getTables(long lengthInMillis) throws MetaStoreException {
    return AccessCountTableManager.getTables(tableDeques, metaStore, lengthInMillis);
  }

  public static List<AccessCountTable> getTables(
      Map<TimeGranularity, AccessCountTableDeque> tableDeques,
      MetaStore metaStore,
      long lengthInMillis)
      throws MetaStoreException {
    if (tableDeques.isEmpty()) {
      return new ArrayList<>();
    }
    AccessCountTableDeque secondTableDeque = tableDeques.get(TimeGranularity.SECOND);
    if (secondTableDeque == null || secondTableDeque.isEmpty()) {
      return new ArrayList<>();
    }
    long now = secondTableDeque.getLast().getEndTime();
    return getTablesDuring(
        tableDeques, metaStore, lengthInMillis, now, TimeUtils.getGranularity(lengthInMillis));
  }

  // Todo: multi-thread issue
  private static List<AccessCountTable> getTablesDuring(
      final Map<TimeGranularity, AccessCountTableDeque> tableDeques,
      MetaStore metaStore,
      final long length,
      final long endTime,
      final TimeGranularity timeGranularity)
      throws MetaStoreException {
    long startTime = endTime - length;
    AccessCountTableDeque tables = tableDeques.get(timeGranularity);
    List<AccessCountTable> results = new ArrayList<>();
    for (AccessCountTable table : tables) {
      // Here we assume that the tables are all sorted by time.
      if (table.getEndTime() > startTime) {
        if (table.getStartTime() >= startTime) {
          results.add(table);
          startTime = table.getEndTime();
        } else if (table.getStartTime() < startTime) {
          // We got a table should be spilt here. But sometimes we will split out an
          // table that already exists, so this situation should be avoided.
          if (!tableExists(tableDeques, startTime, table.getEndTime())) {
            AccessCountTable splitTable = new AccessCountTable(startTime, table.getEndTime(), true);
            metaStore.createProportionTable(splitTable, table);
            results.add(splitTable);
            startTime = table.getEndTime();
          }
        }
      }
    }
    if (startTime != endTime && !timeGranularity.equals(TimeGranularity.SECOND)) {
      TimeGranularity fineGrained = TimeUtils.getFineGarinedGranularity(timeGranularity);
      results.addAll(
          getTablesDuring(tableDeques, metaStore, endTime - startTime, endTime, fineGrained));
    }
    return results;
  }

  private static boolean tableExists(
      final Map<TimeGranularity, AccessCountTableDeque> tableDeques, long start, long end) {
    TimeGranularity granularity = TimeUtils.getGranularity(end - start);
    AccessCountTable fakeTable = new AccessCountTable(start, end);
    return tableDeques.containsKey(granularity) && tableDeques.get(granularity).contains(fakeTable);
  }

  @VisibleForTesting
  Map<TimeGranularity, AccessCountTableDeque> getTableDeques() {
    return this.tableDeques;
  }
}
