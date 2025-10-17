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

import lombok.Data;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.metastore.IMetaStoreClient;
import org.apache.hadoop.hive.metastore.TableType;
import org.apache.hadoop.hive.metastore.api.AllTableConstraintsRequest;
import org.apache.hadoop.hive.metastore.api.Database;
import org.apache.hadoop.hive.metastore.api.Function;
import org.apache.hadoop.hive.metastore.api.GetAllFunctionsResponse;
import org.apache.hadoop.hive.metastore.api.Partition;
import org.apache.hadoop.hive.metastore.api.SQLAllTableConstraints;
import org.apache.hadoop.hive.metastore.api.Table;
import org.apache.hadoop.hive.metastore.messaging.json.gzip.GzipJSONMessageEncoder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.hive.HiveSmartConf;
import org.smartdata.hive.fetch.HiveEntity;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HiveOperation;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.smartdata.hive.HiveEntityFactory.buildCheckConstraint;
import static org.smartdata.hive.HiveEntityFactory.buildDb;
import static org.smartdata.hive.HiveEntityFactory.buildDefaultConstraint;
import static org.smartdata.hive.HiveEntityFactory.buildForeignKey;
import static org.smartdata.hive.HiveEntityFactory.buildFunction;
import static org.smartdata.hive.HiveEntityFactory.buildNotNullConstraint;
import static org.smartdata.hive.HiveEntityFactory.buildPartition;
import static org.smartdata.hive.HiveEntityFactory.buildPrimaryKey;
import static org.smartdata.hive.HiveEntityFactory.buildTable;
import static org.smartdata.hive.HiveEntityFactory.buildUniqueConstraint;
import static org.smartdata.hive.HiveSmartConf.HMS_FETCH_BATCH_SIZE;
import static org.smartdata.hive.snapshot.HiveNotificationEventFactory.fullName;
import static org.smartdata.hive.snapshot.HiveNotificationEventFactory.partitionName;

public class HmsSnapshotEventSourceTest {
  private final static int TEST_TIMEOUT_SEC = 10;

  private final static int DB_COUNT = 24;
  private final static int TABLE_PER_DB_COUNT = 32;
  private final static int PARTITION_PER_TABLE_COUNT = 10;
  private final static int FUNCTION_COUNT = 16;
  private final static int CONSTRAINT_PER_TABLE_COUNT = 6;

  private final static int TOTAL_EVENTS_COUNT = DB_COUNT
      // tables
      + DB_COUNT * TABLE_PER_DB_COUNT
      // partitions
      + DB_COUNT * TABLE_PER_DB_COUNT * PARTITION_PER_TABLE_COUNT
      // constraints
      + DB_COUNT * TABLE_PER_DB_COUNT * CONSTRAINT_PER_TABLE_COUNT
      // functions
      + FUNCTION_COUNT;

  private MockMetastoreClient metaStoreClient;
  private ExecutorService executorService;
  private HmsSnapshotEventSource snapshotEventSource;

  @Before
  public void init() throws Exception {
    metaStoreClient = new MockMetastoreClient(
        buildDbs(),
        buildFunctions()
    );

    executorService = Executors.newFixedThreadPool(4);

    HiveSmartConf conf = new HiveSmartConf(new Configuration());
    conf.setInt(HMS_FETCH_BATCH_SIZE, 16000);
    snapshotEventSource = HmsSnapshotEventSource.builder()
        .metaStoreClientProvider(() -> metaStoreClient.delegate)
        .executor(executorService)
        .eventFactory(new HiveNotificationEventFactory(GzipJSONMessageEncoder.getInstance()))
        .hiveSmartConf(conf)
        .build();
  }

  @After
  public void shutdown() {
    snapshotEventSource.close();
    executorService.shutdown();
  }

  @Test
  public void testFetch() throws Exception {
    CompletableFuture<Void> future = snapshotEventSource.pollRecordsBatchAsync(0);
    future.get(TEST_TIMEOUT_SEC, TimeUnit.SECONDS);

    Set<EventInfo> actualEvents = snapshotEventSource.getOutputQueue().stream()
        .filter(HiveNotificationEvent.class::isInstance)
        .map(HiveNotificationEvent.class::cast)
        .map(EventInfo::from)
        .collect(Collectors.toSet());

    assertEquals(TOTAL_EVENTS_COUNT, actualEvents.size());
    assertEquals(metaStoreClient.getExpectedEvents(), actualEvents);
  }

  private Map<String, DbInfo> buildDbs() {
    return IntStream.range(0, DB_COUNT)
        .mapToObj(i -> buildDbInfo("db_" + i))
        .collect(Collectors.toMap(
            db -> db.getDelegate().getName(),
            db -> db
        ));
  }

  private DbInfo buildDbInfo(String dbName) {
    Map<String, TableInfo> tables = IntStream.range(0, TABLE_PER_DB_COUNT)
        .mapToObj(i -> buildTableInfo(dbName, "table_" + i))
        .collect(Collectors.toMap(
            TableInfo::getName,
            t -> t
        ));

    return new DbInfo(
        buildDb("hive." + dbName, "/" + dbName), tables);
  }

  private TableInfo buildTableInfo(String dbName, String tableName) {
    String fullName = "hive." + dbName + "." + tableName;
    return new TableInfo(
        tableName,
        buildTable(fullName, TableType.EXTERNAL_TABLE,
            "/" + dbName + "/" + tableName, "column1", "column2"),
        buildConstraints(fullName),
        buildPartitions(fullName)
    );
  }

  private SQLAllTableConstraints buildConstraints(String tableName) {
    SQLAllTableConstraints constraints = new SQLAllTableConstraints();
    constraints.setPrimaryKeys(
        Collections.singletonList(buildPrimaryKey(tableName, "col1"))
    );
    constraints.setForeignKeys(
        Collections.singletonList(buildForeignKey(tableName, "col1"))
    );
    constraints.setUniqueConstraints(
        Collections.singletonList(buildUniqueConstraint(tableName, "col1"))
    );
    constraints.setNotNullConstraints(
        Collections.singletonList(buildNotNullConstraint(tableName, "col1"))
    );
    constraints.setDefaultConstraints(
        Collections.singletonList(buildDefaultConstraint(tableName, "col1"))
    );
    constraints.setCheckConstraints(
        Collections.singletonList(buildCheckConstraint(tableName, "col1"))
    );

    return constraints;
  }

  private List<Partition> buildPartitions(String tableName) {
    return IntStream.range(0, PARTITION_PER_TABLE_COUNT)
        .mapToObj(i -> buildPartition(tableName,
            String.valueOf(i * 10 + 1),
            String.valueOf(i * 10 + 2)))
        .collect(Collectors.toList());
  }

  private List<Function> buildFunctions() {
    return IntStream.range(0, FUNCTION_COUNT)
        .mapToObj(i -> buildFunction("hive.db.function_" + i))
        .collect(Collectors.toList());
  }

  @Data
  private static class EventInfo {
    private final String eventType;
    private final String entityType;
    private final String fullName;

    public static EventInfo of(HiveEntity entity, String... nameParts) {
      return new EventInfo(
          HiveOperation.CREATE.toString(),
          entity.toString(),
          String.join(".", nameParts)
      );
    }

    public static EventInfo from(HiveNotificationEvent event) {
      return new EventInfo(
          event.getEventType(),
          event.getEntityType(),
          event.getFullName()
      );
    }
  }

  @Data
  private static class DbInfo {
    private final Database delegate;
    private final Map<String, TableInfo> tables;
  }

  @Data
  private static class TableInfo {
    private final String name;
    private final Table delegate;
    private final SQLAllTableConstraints constraints;
    private final List<Partition> partitions;
  }

  private static class MockMetastoreClient {
    private final IMetaStoreClient delegate;

    private final Map<String, DbInfo> dbs;
    private final List<Function> functions;

    public MockMetastoreClient(Map<String, DbInfo> dbs, List<Function> functions) throws Exception {
      this.dbs = dbs;
      this.functions = functions;

      this.delegate = mock(IMetaStoreClient.class);
      initMock();
    }

    private void initMock() throws Exception {
      when(delegate.getAllDatabases(anyString()))
          .thenAnswer(invocation -> getAllDatabases());
      when(delegate.getAllFunctions())
          .thenAnswer(invocation -> getAllFunctions());
      when(delegate.getDatabase(anyString()))
          .thenAnswer(invocation -> getDatabase(invocation.getArgument(0)));
      when(delegate.getAllTables(anyString(), anyString()))
          .thenAnswer(invocation -> getAllTables(invocation.getArgument(1)));
      when(delegate.getTableObjectsByName(anyString(), anyString(), any()))
          .thenAnswer(invocation -> getTableObjectsByName(
              invocation.getArgument(1), invocation.getArgument(2)));
      when(delegate.getAllTableConstraints(any()))
          .thenAnswer(invocation -> getAllTableConstraints(invocation.getArgument(0)));
      when(delegate.listPartitions(anyString(), anyString(), anyString(), anyInt()))
          .thenAnswer(invocation ->
              listPartitions(invocation.getArgument(1), invocation.getArgument(2)));
    }

    private Set<EventInfo> getExpectedEvents() {
      Set<EventInfo> events = new HashSet<>();
      events.addAll(functionExpectedEvents());
      events.addAll(dbsExpectedEvents());
      return events;
    }

    private Set<EventInfo> functionExpectedEvents() {
      return functions.stream()
          .map(function -> EventInfo.of(HiveEntity.FUNCTION, fullName(function)))
          .collect(Collectors.toSet());
    }

    private Set<EventInfo> dbsExpectedEvents() {
      return dbs.values()
          .stream()
          .flatMap(db -> dbExpectedEvents(db).stream())
          .collect(Collectors.toSet());
    }

    private Set<EventInfo> dbExpectedEvents(DbInfo dbInfo) {
      Set<EventInfo> events = dbInfo.getTables().values()
          .stream()
          .flatMap(table -> tableExpectedEvents(table).stream())
          .collect(Collectors.toSet());
      events.add(EventInfo.of(HiveEntity.DATABASE, dbInfo.delegate.getName()));
      return events;
    }

    private Set<EventInfo> tableExpectedEvents(TableInfo tableInfo) {
      Set<EventInfo> events = tableInfo.partitions.stream()
          .map(partition -> EventInfo.of(HiveEntity.PARTITION,
              partitionName(tableInfo.delegate, partition)))
          .collect(Collectors.toSet());

      events.addAll(constraintsExpectedEvents(tableInfo.constraints));
      events.add(EventInfo.of(HiveEntity.TABLE, fullName(tableInfo.delegate)));
      return events;
    }

    private Set<EventInfo> constraintsExpectedEvents(SQLAllTableConstraints constraints) {
      return Stream.of(
          EventInfo.of(HiveEntity.PRIMARY_KEY, fullName(constraints.getPrimaryKeys().get(0))),
          EventInfo.of(HiveEntity.FOREIGN_KEY, fullName(constraints.getForeignKeys().get(0))),
          EventInfo.of(HiveEntity.UNIQUE_CONSTRAINT, fullName(constraints.getUniqueConstraints().get(0))),
          EventInfo.of(HiveEntity.NOT_NULL_CONSTRAINT, fullName(constraints.getNotNullConstraints().get(0))),
          EventInfo.of(HiveEntity.DEFAULT_CONSTRAINT, fullName(constraints.getDefaultConstraints().get(0))),
          EventInfo.of(HiveEntity.CHECK_CONSTRAINT, fullName(constraints.getCheckConstraints().get(0)))
      ).collect(Collectors.toSet());
    }

    private List<String> getAllDatabases() {
      return dbs.values()
          .stream()
          .map(DbInfo::getDelegate)
          .map(Database::getName)
          .collect(Collectors.toList());
    }

    private GetAllFunctionsResponse getAllFunctions() {
      GetAllFunctionsResponse response = new GetAllFunctionsResponse();
      response.setFunctions(functions);
      return response;
    }

    private Database getDatabase(String dbName) {
      return getDbInfo(dbName).getDelegate();
    }

    private List<String> getAllTables(String dbName) {
      return getDbTables(dbName)
          .stream()
          .map(TableInfo::getName)
          .collect(Collectors.toList());
    }

    private List<Table> getTableObjectsByName(String dbName, List<String> tableNames) {
      return getDbTables(dbName)
          .stream()
          .filter(table -> tableNames.contains(table.name))
          .map(TableInfo::getDelegate)
          .collect(Collectors.toList());
    }

    private SQLAllTableConstraints getAllTableConstraints(AllTableConstraintsRequest request) {
      return getDbTableInfo(request.getDbName(), request.getTblName()).getConstraints();
    }

    private List<Partition> listPartitions(String dbName, String tblName) {
      return getDbTableInfo(dbName, tblName).getPartitions();
    }

    private DbInfo getDbInfo(String dbName) {
      return Optional.ofNullable(dbs.get(dbName))
          .orElseThrow(() -> new IllegalArgumentException("Wrong db name: " + dbName));
    }

    private Collection<TableInfo> getDbTables(String dbName) {
      return getDbInfo(dbName)
          .getTables()
          .values();
    }

    private TableInfo getDbTableInfo(String dbName, String tblName) {
      return getDbInfo(dbName)
          .getTables()
          .computeIfAbsent(tblName, ignore -> {
            throw new IllegalArgumentException("Invalid table name " + tblName);
          });
    }
  }
}