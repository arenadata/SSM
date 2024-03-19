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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;

public class AggregatingTableAddOpListener implements TableAddOpListener {
  static final Logger LOG = LoggerFactory.getLogger(AggregatingTableAddOpListener.class);

  private final AccessCountTableDeque coarseGrainedTableDeque;
  private final AccessCountTableAggregator tableAggregator;
  private final ExecutorService executorService;
  private final Set<AccessCountTable> tablesUnderConstruction;
  private final long millisPerGranularity;

  AggregatingTableAddOpListener(
      AccessCountTableDeque deque,
      AccessCountTableAggregator aggregator,
      ExecutorService executorService,
      long millisPerGranularity) {
    this.coarseGrainedTableDeque = deque;
    this.tableAggregator = aggregator;
    this.executorService = executorService;
    this.millisPerGranularity = millisPerGranularity;
    tablesUnderConstruction = ConcurrentHashMap.newKeySet();
  }

  @Override
  public CompletableFuture<AccessCountTable> tableAdded(
      AccessCountTableDeque fineGrainedTableDeque, AccessCountTable table) {
    final AccessCountTable lastCoarseGrainedTable = lastCoarseGrainedTableFor(table.getEndTime());

    // Todo: optimize contains
    if (coarseGrainedTableDeque.contains(lastCoarseGrainedTable)) {
      return CompletableFuture.completedFuture(lastCoarseGrainedTable);
    }

    final List<AccessCountTable> tablesToAggregate =
        fineGrainedTableDeque.getTables(
            lastCoarseGrainedTable.getStartTime(), lastCoarseGrainedTable.getEndTime());

    if (!tablesToAggregate.isEmpty()
        && !tablesUnderConstruction.contains(lastCoarseGrainedTable)) {
      tablesUnderConstruction.add(lastCoarseGrainedTable);
      return aggregateTableAsync(lastCoarseGrainedTable, tablesToAggregate);
    }

    return TableAddOpListener.EMPTY_RESULT;
  }

  private CompletableFuture<AccessCountTable> aggregateTableAsync(
      AccessCountTable lastCoarseGrainedTable, List<AccessCountTable> tablesToAggregate) {
    return CompletableFuture.supplyAsync(
        () -> aggregateTable(lastCoarseGrainedTable, tablesToAggregate), executorService);
  }

  private AccessCountTable aggregateTable(
      AccessCountTable lastCoarseGrainedTable, List<AccessCountTable> tablesToAggregate) {
    try {
      tableAggregator.aggregate(lastCoarseGrainedTable, tablesToAggregate);
      coarseGrainedTableDeque.addAndNotifyListener(lastCoarseGrainedTable);
    } catch (Exception e) {
      LOG.error(
          "Add AccessCount Table {} error",
          lastCoarseGrainedTable.getTableName(), e);
    }
    tablesUnderConstruction.remove(lastCoarseGrainedTable);
    return lastCoarseGrainedTable;
  }

  protected AccessCountTable lastCoarseGrainedTableFor(long endTime) {
    long lastEnd = endTime - (endTime % millisPerGranularity);
    long lastStart = lastEnd - millisPerGranularity;
    return new AccessCountTable(lastStart, lastEnd);
  }
  // Todo: WeekTableListener, MonthTableListener, YearTableListener
}
