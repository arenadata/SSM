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
import org.apache.hadoop.hive.metastore.api.GetTableRequest;
import org.apache.hadoop.hive.metastore.api.SQLAllTableConstraints;
import org.apache.hadoop.hive.metastore.api.Table;
import org.apache.hadoop.hive.metastore.utils.MetaStoreUtils;
import org.smartdata.hive.HiveSmartConf;
import org.smartdata.hive.fetch.BaseHmsEventSource;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HmsEventStream;
import org.smartdata.hive.fetch.HmsEventStreamRecord;
import org.smartdata.utils.ThrowingFunction;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiFunction;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.smartdata.hdfs.HadoopUtil.doAsCurrentUser;

@Slf4j
public class HmsSnapshotEventSource extends BaseHmsEventSource {
  public static final long SNAPSHOT_EVENT_ID = -1L;

  private final Supplier<IMetaStoreClient> metaStoreClientProvider;
  private final ExecutorService executor;
  private final String defaultCatalog;

  @Getter
  private final BlockingQueue<HmsEventStreamRecord> outputQueue;
  private final AtomicBoolean pollStarted;

  private final HiveNotificationEventFactory eventFactory;

  @lombok.Builder(builderClassName = "Builder")
  public HmsSnapshotEventSource(
      Supplier<IMetaStoreClient> metaStoreClientProvider,
      ExecutorService executor,
      HiveNotificationEventFactory eventFactory,
      HiveSmartConf hiveSmartConf
  ) {
    this.metaStoreClientProvider = metaStoreClientProvider;
    this.executor = executor;
    this.outputQueue = new ArrayBlockingQueue<>(hiveSmartConf.getFetchBatchSize());
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
      pollRecordsBatchAsync(eventId);
    }
    return HmsEventStream.withoutIgnoredEvents(outputQueue);
  }

  @Override
  protected void closeAction() {
    outputQueue.add(HmsEventStreamRecord.endOfStreamRecord());
    executor.shutdown();
  }

  CompletableFuture<Void> pollRecordsBatchAsync(long diffId) {
    return supplyWithMetastoreClient(client -> client.getAllDatabases(defaultCatalog))
        .thenCompose(dbs -> executeInParallel(dbs, diffId, this::handleDb))
        .thenCompose(ignore -> handleFunctions(diffId))
        .thenRun(() -> send(HmsEventStreamRecord.endOfStreamRecord()))
        .thenRun(() -> log.info("Hive metastore snapshot is successfully done"))
        .exceptionally(error -> {
          handleError(error);
          return null;
        });
  }

  private CompletableFuture<Void> handleFunctions(long diffId) {
    return supplyWithMetastoreClient(client -> client.getAllFunctions().getFunctions())
        .thenAccept(functions -> functions.stream()
            .map(function -> eventFactory.createFunctionEvent(function, diffId))
            .forEach(this::send));
  }

  private CompletableFuture<Void> handleDb(String dbName, long diffId) {
    return supplyWithMetastoreClient(client -> {
      Database database = client.getDatabase(dbName);
      send(eventFactory.createDbEvent(database, diffId));
      return database;
    }).thenComposeAsync(db -> handleTables(db, diffId), executor);
  }

  private CompletableFuture<Void> handleTables(Database db, long diffId) {
    List<String> tables = withMetastoreClient(
        client -> client.getAllTables(db.getCatalogName(), db.getName()));
    return executeInParallel(tables, diffId,
        (table, ignore) -> handleTable(db, table, diffId));
  }

  private CompletableFuture<Void> handleTable(Database db, String tableName, long diffId) {
    GetTableRequest request = new GetTableRequest(db.getName(), tableName);
    request.setCatName(db.getCatalogName());
    request.setGetColumnStats(true);

    return supplyWithMetastoreClient(client -> client.getTable(request))
        .thenComposeAsync(table -> handleTable(table, diffId), executor);
  }

  private CompletableFuture<Void> handleTable(Table table, long diffId) {
    send(eventFactory.createTableEvent(table, diffId));

    return CompletableFuture.allOf(
        handlePartitions(table, diffId),
        handleConstraints(table, diffId)
    );
  }

  private CompletableFuture<Void> handleConstraints(Table table, long diffId) {
    return supplyWithMetastoreClient(client -> client.getAllTableConstraints(
        new AllTableConstraintsRequest(
            table.getDbName(),
            table.getTableName(),
            table.getCatName()
        )
    )).thenAccept(constraints -> handleConstraints(constraints, diffId));
  }

  private void handleConstraints(SQLAllTableConstraints allTableConstraints, long diffId) {
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

  private CompletableFuture<Void> handlePartitions(Table table, long diffId) {
    return supplyWithMetastoreClient(client -> client.listPartitions(
        table.getCatName(), table.getDbName(), table.getTableName(), (short) -1))
        .thenAccept(partitions -> partitions.stream()
            .map(partition -> eventFactory.createPartitionEvent(table, partition, diffId))
            .forEach(this::send));
  }

  private <T> void handleConstraint(
      long diffId,
      List<T> constraints,
      BiFunction<T, Long, HiveNotificationEvent> handler) {

    for (T constraint : CollectionUtils.emptyIfNull(constraints)) {
      send(handler.apply(constraint, diffId));
    }
  }

  private <V> CompletableFuture<V> supplyWithMetastoreClient(
      ThrowingFunction<IMetaStoreClient, V, Exception> function) {
    return CompletableFuture.supplyAsync(() -> withMetastoreClient(function), executor);
  }

  private void handleError(Throwable exception) {
    log.error("Error polling records batch from Hive Metastore", exception);
    close();
  }

  private <V> V withMetastoreClient(ThrowingFunction<IMetaStoreClient, V, Exception> function) {
    throwIfClosed();
    try (IMetaStoreClient client = metaStoreClientProvider.get()) {
      return doAsCurrentUser(() -> function.apply(client));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private <T> CompletableFuture<Void> executeInParallel(
      Collection<T> entities,
      long diffId,
      BiFunction<T, Long, CompletableFuture<?>> transformer) {
    return executeInParallel(entities.stream(), diffId, transformer);
  }

  private <T> CompletableFuture<Void> executeInParallel(
      Stream<T> entities,
      long diffId,
      BiFunction<T, Long, CompletableFuture<?>> transformer) {
    throwIfClosed();
    return CompletableFuture.allOf(
        entities
            .map(entity -> transformer.apply(entity, diffId))
            .toArray(CompletableFuture[]::new)
    );
  }

  private void send(HmsEventStreamRecord record) {
    try {
      throwIfClosed();
      outputQueue.put(record);
    } catch (InterruptedException e) {
      throw new RuntimeException("Thread interrupted during event send", e);
    }
  }

  private void throwIfClosed() {
    if (isClosed()) {
      throw new CancellationException("HmsEventSource is closed");
    }
  }
}
