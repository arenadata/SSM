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

package org.smartdata.hive.snapshot;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.hadoop.hive.metastore.IMetaStoreClient;
import org.apache.hadoop.hive.metastore.api.AllTableConstraintsRequest;
import org.apache.hadoop.hive.metastore.api.Database;
import org.apache.hadoop.hive.metastore.api.Function;
import org.apache.hadoop.hive.metastore.api.Partition;
import org.apache.hadoop.hive.metastore.api.SQLAllTableConstraints;
import org.apache.hadoop.hive.metastore.api.Table;
import org.apache.hadoop.hive.metastore.utils.MetaStoreUtils;
import org.apache.hadoop.thirdparty.com.google.common.collect.Iterables;
import org.apache.thrift.TException;
import org.smartdata.hive.HiveSmartConf;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HmsEventSource;
import org.smartdata.hive.fetch.HmsEventStream;
import org.smartdata.hive.fetch.HmsEventStreamRecord;
import org.smartdata.retry.RetryException;
import org.smartdata.retry.RetrySupport;

import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiFunction;

import static org.smartdata.hdfs.HadoopUtil.doAsCurrentUser;

@Slf4j
public class HmsSnapshotEventSource implements HmsEventSource {
  public static final long SNAPSHOT_EVENT_ID = -1L;

  private final IMetaStoreClient metaStoreClient;
  private final ExecutorService executor;
  private final RetrySupport retrySupport;
  private final int eventBatchSize;
  private final String defaultCatalog;

  @Getter
  private final BlockingQueue<HmsEventStreamRecord> outputQueue;
  private final AtomicBoolean pollStarted;

  private final HiveNotificationEventFactory eventFactory;

  @lombok.Builder(builderClassName = "Builder")
  public HmsSnapshotEventSource(
      IMetaStoreClient metaStoreClient,
      ExecutorService executor,
      RetrySupport retrySupport,
      HiveNotificationEventFactory eventFactory,
      HiveSmartConf hiveSmartConf
  ) {
    this.metaStoreClient = metaStoreClient;
    this.executor = executor;
    this.eventBatchSize = hiveSmartConf.getFetchBatchSize();
    this.outputQueue = new ArrayBlockingQueue<>(eventBatchSize);
    this.retrySupport = retrySupport;
    this.eventFactory = eventFactory;
    this.pollStarted = new AtomicBoolean(false);
    this.defaultCatalog = MetaStoreUtils.getDefaultCatalog(hiveSmartConf);
  }

  @Override
  public HmsEventStream eventStream() {
    return eventStreamFrom(SNAPSHOT_EVENT_ID);
  }

  @Override
  public HmsEventStream eventStreamFrom(long eventId) {
    if (pollStarted.compareAndSet(false, true)) {
      executor.submit(() -> pollRecordsBatch(eventId));
    }
    return HmsEventStream.withoutIgnoredEvents(outputQueue);
  }

  void pollRecordsBatch(long diffId) {
    try {
      retrySupport.withRetries(
          () -> doAsCurrentUser(() -> pollRecordsBatchAction(diffId))
      );
    } catch (RetryException retryException) {
      log.error("Exiting HiveMetastoreEventFetcher due to error", retryException);
      close();
    }
  }

  private void pollRecordsBatchAction(long diffId) {
    try {
      snapshotMetastore(diffId);
    } catch (Exception e) {
      throw new RuntimeException("Error polling records batch from Hive Metastore", e);
    }
  }

  private void snapshotMetastore(long diffId) throws Exception {
    for (String dbName : metaStoreClient.getAllDatabases(defaultCatalog)) {
      handleDb(dbName, diffId);
    }

    for (Function function : metaStoreClient.getAllFunctions().getFunctions()) {
      send(eventFactory.createFunctionEvent(function, diffId));
    }

    send(HmsEventStreamRecord.endOfStreamRecord());
  }

  private void handleDb(String dbName, long diffId) throws Exception {
    Database database = metaStoreClient.getDatabase(dbName);
    send(eventFactory.createDbEvent(database.getCatalogName(), database, diffId));

    List<String> allTables = metaStoreClient.getAllTables(database.getCatalogName(), database.getName());

    for (List<String> tableNamesBatch : Iterables.partition(allTables, eventBatchSize)) {
      for (Table table : metaStoreClient.getTableObjectsByName(
          database.getCatalogName(), database.getName(), tableNamesBatch)) {
        handleTable(table, diffId);
      }
    }
  }

  // todo parallelize
  private void handleTable(Table table, long diffId) throws Exception {
    send(eventFactory.createTableEvent(table, diffId));

    handlePartitions(table, diffId);
    handleConstraints(table, diffId);
  }

  private void handleConstraints(Table table, long diffId) throws Exception {
    AllTableConstraintsRequest request = new AllTableConstraintsRequest(
        table.getDbName(),
        table.getTableName(),
        table.getCatName()
    );
    SQLAllTableConstraints allTableConstraints = metaStoreClient.getAllTableConstraints(request);

    handleConstraint(
        diffId,
        allTableConstraints.getPrimaryKeys(),
        eventFactory::createPrimaryKeyEvent
    );

    handleConstraint(
        diffId,
        allTableConstraints.getForeignKeys(),
        eventFactory::createForeignKeyEvent
    );

    handleConstraint(
        diffId,
        allTableConstraints.getUniqueConstraints(),
        eventFactory::createUniqueConstraintEvent
    );

    handleConstraint(
        diffId,
        allTableConstraints.getNotNullConstraints(),
        eventFactory::createNotNullConstraintEvent
    );

    handleConstraint(
        diffId,
        allTableConstraints.getDefaultConstraints(),
        eventFactory::createDefaultConstraintEvent
    );

    handleConstraint(
        diffId,
        allTableConstraints.getCheckConstraints(),
        eventFactory::createCheckConstraintEvent
    );
  }

  private void handlePartitions(Table table, long diffId) throws TException {
    for (Partition partition : metaStoreClient.listPartitions(
        table.getCatName(), table.getDbName(), table.getTableName(), (short) -1)) {
      send(eventFactory.createPartitionEvent(table, partition, diffId));
    }
  }

  private void send(HmsEventStreamRecord record) {
    outputQueue.add(record);
  }

  private <T> void handleConstraint(
      long diffId,
      List<T> constraints,
      BiFunction<T, Long, HiveNotificationEvent> handler) {

    for (T constraint : CollectionUtils.emptyIfNull(constraints)) {
      send(handler.apply(constraint, diffId));
    }
  }

  @Override
  public void close() {
    if (executor != null) {
      executor.shutdown();
    }

    outputQueue.add(HmsEventStreamRecord.endOfStreamRecord());
  }
}
