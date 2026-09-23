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
package org.smartdata.hive.catalog;

import com.google.common.collect.Sets;
import org.apache.hadoop.hive.metastore.TableType;
import org.apache.hadoop.hive.metastore.api.Database;
import org.apache.hadoop.hive.metastore.api.NotificationEvent;
import org.apache.hadoop.hive.metastore.api.Partition;
import org.apache.hadoop.hive.metastore.api.Table;
import org.apache.hadoop.hive.metastore.messaging.json.JSONMessageEncoder;
import org.apache.hadoop.hive.metastore.messaging.json.gzip.GzipJSONMessageEncoder;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.hive.EntityInfo;
import org.smartdata.hive.fetch.EventOperation;
import org.smartdata.hive.fetch.EventOperationBuilder;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HmsEventStreamRecord;
import org.smartdata.hive.snapshot.HiveNotificationEventFactory;
import org.smartdata.retry.PolicyBasedRetrySupport;
import org.smartdata.retry.RetrySupport;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionCallback;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.smartdata.hive.HiveEntityFactory.buildDb;
import static org.smartdata.hive.HiveEntityFactory.buildFunction;
import static org.smartdata.hive.HiveEntityFactory.buildPartition;
import static org.smartdata.hive.HiveEntityFactory.buildPartitionWithLocation;
import static org.smartdata.hive.HiveEntityFactory.buildTable;
import static org.smartdata.hive.NotificationEventFactory.newAddPartitionEvent;
import static org.smartdata.hive.NotificationEventFactory.newAlterDbEvent;
import static org.smartdata.hive.NotificationEventFactory.newAlterPartitionEvent;
import static org.smartdata.hive.NotificationEventFactory.newAlterTableEvent;
import static org.smartdata.hive.NotificationEventFactory.newCreateDbEvent;
import static org.smartdata.hive.NotificationEventFactory.newCreateTableEvent;
import static org.smartdata.hive.NotificationEventFactory.newDropDbEvent;
import static org.smartdata.hive.NotificationEventFactory.newDropPartitionEvent;
import static org.smartdata.hive.NotificationEventFactory.newDropTableEvent;
import static org.smartdata.hive.fetch.HiveNotificationEvent.fullResourceName;
import static org.smartdata.retry.RetryPolicyFactory.NO_RETRIES_POLICY;

public class CatalogHmsEventHandlerTest {
  private static final String SALES_LOCATION = "hdfs://ns1/warehouse/db1.db/sales";

  private static final RetrySupport NO_RETRIES = new PolicyBasedRetrySupport(
      NO_RETRIES_POLICY, ignore -> {});

  private InMemoryHiveCatalogDao catalogDao;
  private CatalogHmsEventHandler catalogHandler;
  private HiveNotificationEventFactory snapshotEventFactory;
  private long nextEventId;

  @Before
  public void init() {
    catalogDao = new InMemoryHiveCatalogDao();
    catalogHandler = new CatalogHmsEventHandler(catalogDao, NO_RETRIES);
    snapshotEventFactory = new HiveNotificationEventFactory(GzipJSONMessageEncoder.getInstance());
    nextEventId = 1;
  }

  @Test
  public void testHandleCreateEvents() throws Exception {
    handle(
        newCreateDbEvent(1, "hive.db1", "hdfs://ns1/warehouse/db1.db"),
        newCreateTableEvent(2, "hive.db1.tbl1", TableType.MANAGED_TABLE,
            "hdfs://ns1/warehouse/db1.db/tbl1"),
        newCreateTableEvent(3, "hive.db1.ext", TableType.EXTERNAL_TABLE, "hdfs://ns1/external/ext")
    );

    HiveDatabaseInfo expectedDb = HiveDatabaseInfo.builder()
        .name("db1")
        .catalogName("hive")
        .location("hdfs://ns1/warehouse/db1.db")
        .build();
    assertEquals(expectedDb, catalogDao.databases.get("db1"));

    HiveTableInfo expectedTable = HiveTableInfo.builder()
        .dbName("db1")
        .name("tbl1")
        .catalogName("hive")
        .location("hdfs://ns1/warehouse/db1.db/tbl1")
        .build();
    assertEquals(expectedTable, catalogDao.tables.get("db1.tbl1"));
    assertEquals("hdfs://ns1/external/ext", catalogDao.tables.get("db1.ext").getLocation());
  }

  @Test
  public void testHandleSnapshotEvents() throws Exception {
    Database database = buildDb("hive.db1", "hdfs://ns1/warehouse/db1.db");
    // managed location isn't stored in the catalog
    database.setManagedLocationUri("hdfs://ns1/managed/db1.db");

    Table table = buildTable("hive.db1.tbl1", TableType.MANAGED_TABLE,
        "hdfs://ns1/managed/db1.db/tbl1", "year", "month");

    catalogHandler.handle(snapshotEventFactory.createDbEvent(database, 1));
    catalogHandler.handle(snapshotEventFactory.createTableEvent(table, 2));

    HiveDatabaseInfo expectedDb = HiveDatabaseInfo.builder()
        .name("db1")
        .catalogName("hive")
        .location("hdfs://ns1/warehouse/db1.db")
        .build();
    assertEquals(expectedDb, catalogDao.databases.get("db1"));

    HiveTableInfo expectedTable = HiveTableInfo.builder()
        .dbName("db1")
        .name("tbl1")
        .catalogName("hive")
        .location("hdfs://ns1/managed/db1.db/tbl1")
        .build();
    assertEquals(expectedTable, catalogDao.tables.get("db1.tbl1"));
  }

  @Test
  public void testHandleCreateEventForExistingEntity() throws Exception {
    handle(
        newCreateTableEvent(1, "hive.db1.tbl1", TableType.MANAGED_TABLE, "hdfs://ns1/old"),
        newCreateTableEvent(2, "hive.db1.tbl1", TableType.EXTERNAL_TABLE, "hdfs://ns1/new")
    );

    assertEquals("hdfs://ns1/new", catalogDao.tables.get("db1.tbl1").getLocation());
    assertEquals(1, catalogDao.tables.size());
  }

  @Test
  public void testHandleAlterTableLocation() throws Exception {
    handle(
        newCreateTableEvent(1, "hive.db1.tbl1", TableType.EXTERNAL_TABLE, "hdfs://ns1/old"),
        newAlterTableEvent(2, TableType.EXTERNAL_TABLE,
            new EntityInfo("hive.db1.tbl1", "hdfs://ns1/old"),
            new EntityInfo("hive.db1.tbl1", "hdfs://ns1/new"))
    );

    assertEquals(Collections.singletonMap("db1.tbl1", table("db1", "tbl1", "hdfs://ns1/new")),
        catalogDao.tables);
  }

  @Test
  public void testHandleAlterTableRename() throws Exception {
    handle(
        newCreateTableEvent(1, "hive.db1.tbl1", TableType.MANAGED_TABLE, "hdfs://ns1/db1.db/tbl1"),
        newAlterTableEvent(2, TableType.MANAGED_TABLE,
            new EntityInfo("hive.db1.tbl1", "hdfs://ns1/db1.db/tbl1"),
            new EntityInfo("hive.db2.renamed", "hdfs://ns1/db2.db/renamed"))
    );

    assertEquals(
        Collections.singletonMap("db2.renamed", table("db2", "renamed", "hdfs://ns1/db2.db/renamed")),
        catalogDao.tables);
  }

  @Test
  public void testHandleAlterDatabase() throws Exception {
    handle(
        newCreateDbEvent(1, "hive.db1", "hdfs://ns1/old/db1.db"),
        newCreateTableEvent(2, "hive.db1.tbl1", TableType.MANAGED_TABLE, "hdfs://ns1/old/db1.db/tbl1"),
        newAlterDbEvent(3,
            new EntityInfo("hive.db1", "hdfs://ns1/old/db1.db"),
            new EntityInfo("hive.db1", "hdfs://ns1/new/db1.db"))
    );

    assertEquals("hdfs://ns1/new/db1.db", catalogDao.databases.get("db1").getLocation());
    // tables are not affected by the database alteration
    assertTrue(catalogDao.tables.containsKey("db1.tbl1"));
  }

  @Test
  public void testHandleDropTable() throws Exception {
    handle(
        newCreateTableEvent(1, "hive.db1.tbl1", TableType.MANAGED_TABLE, "hdfs://ns1/db1.db/tbl1"),
        newCreateTableEvent(2, "hive.db1.tbl2", TableType.MANAGED_TABLE, "hdfs://ns1/db1.db/tbl2"),
        newDropTableEvent(3, "hive.db1.tbl1", TableType.MANAGED_TABLE, "hdfs://ns1/db1.db/tbl1"),
        // dropping of non-existent table shouldn't fail
        newDropTableEvent(4, "hive.db1.unknown", TableType.MANAGED_TABLE, "hdfs://ns1/db1.db/unknown")
    );

    assertEquals(1, catalogDao.tables.size());
    assertTrue(catalogDao.tables.containsKey("db1.tbl2"));
  }

  @Test
  public void testHandleDropDatabase() throws Exception {
    handle(
        newCreateDbEvent(1, "hive.db1", "hdfs://ns1/db1.db"),
        newCreateDbEvent(2, "hive.db2", "hdfs://ns1/db2.db"),
        newDropDbEvent(3, "hive.db1", "hdfs://ns1/db1.db")
    );

    assertEquals(Collections.singleton("db2"), catalogDao.databases.keySet());
  }

  @Test
  public void testIgnoreNonCatalogRecords() throws Exception {
    catalogHandler.handle(snapshotEventFactory.createFunctionEvent(buildFunction("hive.db1.func"), 1));
    catalogHandler.handle(new HmsEventStreamRecord() {
      @Override
      public boolean isLastRecord() {
        return true;
      }
    });

    assertTrue(catalogDao.databases.isEmpty());
    assertTrue(catalogDao.tables.isEmpty());
  }

  @Test
  public void testFailOnInvalidMessage() {
    HiveNotificationEvent invalidEvent = inFlightEvent(
        newCreateTableEvent(1, "hive.db1.tbl1", TableType.MANAGED_TABLE, "hdfs://ns1/tbl1"))
        .toBuilder()
        .message("not a json")
        .build();

    assertThrows(Exception.class, () -> catalogHandler.handle(invalidEvent));
    assertTrue(catalogDao.tables.isEmpty());
  }

  @Test
  public void testFailOnMissingMessageFormat() {
    HiveNotificationEvent event = inFlightEvent(
        newCreateTableEvent(1, "hive.db1.tbl1", TableType.MANAGED_TABLE, "hdfs://ns1/tbl1"))
        .toBuilder()
        .messageFormat(null)
        .build();

    assertThrows(IllegalArgumentException.class, () -> catalogHandler.handle(event));
    assertTrue(catalogDao.tables.isEmpty());
  }

  @Test
  public void testSkipTablesWithoutPhysicalLocation() throws Exception {
    handle(
        newCreateTableEvent(1, "hive.db1.view", TableType.VIRTUAL_VIEW, null),
        newCreateTableEvent(2, "hive.db1.mat_view", TableType.MATERIALIZED_VIEW, "hdfs://ns1/db1.db/mat_view"),
        newCreateTableEvent(3, "hive.db1.no_location", TableType.MANAGED_TABLE, ""),
        newCreateTableEvent(4, "hive.db1.tbl", TableType.EXTERNAL_TABLE, "hdfs://ns1/tbl")
    );

    assertEquals(Sets.newHashSet("db1.tbl", "db1.mat_view"), catalogDao.tables.keySet());
  }

  @Test
  public void testSkipAlteredAndDroppedView() throws Exception {
    handle(
        newCreateTableEvent(1, "hive.db1.view", TableType.VIRTUAL_VIEW, null),
        newAlterTableEvent(2, TableType.VIRTUAL_VIEW,
            new EntityInfo("hive.db1.view", null),
            new EntityInfo("hive.db1.renamed_view", null)),
        newDropTableEvent(3, "hive.db1.renamed_view", TableType.VIRTUAL_VIEW, null)
    );

    assertTrue(catalogDao.tables.isEmpty());
    // no catalog updates are executed for views
    assertEquals(0, catalogDao.transactionsCount);
  }

  @Test
  public void testHandleAddPartitions() throws Exception {
    handle(newAddPartitionEvent(1, salesTable(),
        partition("2025", SALES_LOCATION + "/year=2025"),
        partition("2024", "hdfs://ns2/archive/sales/2024"),
        partition("2023", "")));

    assertEquals(Sets.newHashSet("db1.sales.year=2025", "db1.sales.year=2024"),
        catalogDao.partitions.keySet());

    HivePartitionInfo expectedPartition = HivePartitionInfo.builder()
        .dbName("db1")
        .tableName("sales")
        .name("year=2024")
        .location("hdfs://ns2/archive/sales/2024")
        .build();
    assertEquals(expectedPartition, catalogDao.partitions.get("db1.sales.year=2024"));
  }

  @Test
  public void testHandleSnapshotPartitionEvent() throws Exception {
    catalogHandler.handle(snapshotEventFactory.createPartitionEvent(
        salesTable(), partition("2025", SALES_LOCATION + "/year=2025"), 1));

    assertEquals(SALES_LOCATION + "/year=2025",
        catalogDao.partitions.get("db1.sales.year=2025").getLocation());
  }

  @Test
  public void testSkipPartitionsOfView() throws Exception {
    Table view = buildTable("hive.db1.view", TableType.VIRTUAL_VIEW, null, "year");
    Partition viewPartition = buildPartition("hive.db1.view", "2025");

    handle(
        newAddPartitionEvent(1, view, viewPartition),
        newAlterPartitionEvent(2, view, viewPartition, buildPartition("hive.db1.view", "2026")),
        newDropPartitionEvent(3, view, viewPartition)
    );

    assertTrue(catalogDao.partitions.isEmpty());
    assertEquals(0, catalogDao.transactionsCount);
  }

  @Test
  public void testHandleAlterPartitionLocation() throws Exception {
    Partition partitionBefore = partition("2025", SALES_LOCATION + "/year=2025");
    Partition partitionAfter = partition("2025", "hdfs://ns1/moved/2025");

    handle(
        newAddPartitionEvent(1, salesTable(), partitionBefore),
        newAlterPartitionEvent(2, salesTable(), partitionBefore, partitionAfter)
    );

    assertEquals(
        Collections.singletonMap("db1.sales.year=2025",
            partitionInfo("year=2025", "hdfs://ns1/moved/2025")),
        catalogDao.partitions);
  }

  @Test
  public void testSkipPartitionStatisticsAlteration() throws Exception {
    Partition partitionBefore = partition("2025", SALES_LOCATION + "/year=2025");
    Partition partitionAfter = partitionBefore.deepCopy();
    partitionAfter.putToParameters("numRows", "100");

    handle(
        newAddPartitionEvent(1, salesTable(), partitionBefore),
        newAlterPartitionEvent(2, salesTable(), partitionBefore, partitionAfter)
    );

    // only the partition adding is applied
    assertEquals(1, catalogDao.transactionsCount);
  }

  @Test
  public void testHandleAlterPartitionRename() throws Exception {
    Partition partitionBefore = partition("2025", SALES_LOCATION + "/year=2025");
    Partition partitionAfter = partition("2026", SALES_LOCATION + "/year=2025");

    handle(
        newAddPartitionEvent(1, salesTable(), partitionBefore),
        newAlterPartitionEvent(2, salesTable(), partitionBefore, partitionAfter)
    );

    assertEquals(
        Collections.singletonMap("db1.sales.year=2026",
            partitionInfo("year=2026", SALES_LOCATION + "/year=2025")),
        catalogDao.partitions);
  }

  @Test
  public void testHandleDropPartitions() throws Exception {
    Partition partition2025 = partition("2025", SALES_LOCATION + "/year=2025");
    Partition partition2024 = partition("2024", SALES_LOCATION + "/year=2024");
    Partition partition2023 = partition("2023", SALES_LOCATION + "/year=2023");

    handle(
        newAddPartitionEvent(1, salesTable(), partition2025, partition2024, partition2023),
        newDropPartitionEvent(2, salesTable(), partition2025, partition2023),
        // dropping of non-existent partition shouldn't fail
        newDropPartitionEvent(3, salesTable(), partition("2000", SALES_LOCATION + "/year=2000"))
    );

    assertEquals(Collections.singleton("db1.sales.year=2024"), catalogDao.partitions.keySet());
  }

  private static HiveTableInfo table(String dbName, String name, String location) {
    return HiveTableInfo.builder()
        .dbName(dbName)
        .name(name)
        .catalogName("hive")
        .location(location)
        .build();
  }

  private static Table salesTable() {
    return buildTable("hive.db1.sales", TableType.EXTERNAL_TABLE, SALES_LOCATION, "year");
  }

  private static HivePartitionInfo partitionInfo(String name, String location) {
    return HivePartitionInfo.builder()
        .dbName("db1")
        .tableName("sales")
        .name(name)
        .location(location)
        .build();
  }

  private static Partition partition(String year, String location) {
    return buildPartitionWithLocation("hive.db1.sales", location, year);
  }

  private void handle(NotificationEvent... events) throws Exception {
    for (NotificationEvent event : events) {
      catalogHandler.handle(inFlightEvent(event));
    }
  }

  private HiveNotificationEvent inFlightEvent(NotificationEvent event) {
    event.setMessageFormat(JSONMessageEncoder.FORMAT);
    EventOperation operation = new EventOperationBuilder().from(event);

    return HiveNotificationEvent.fromMetastoreEvent(event)
        .id(nextEventId++)
        .entityType(operation.getEntity().toString())
        .eventType(operation.getOperation().toString())
        .build();
  }

  static class InMemoryHiveCatalogDao implements HiveCatalogDao {
    final Map<String, HiveDatabaseInfo> databases = new HashMap<>();
    final Map<String, HiveTableInfo> tables = new HashMap<>();
    final Map<String, HivePartitionInfo> partitions = new HashMap<>();
    int transactionsCount = 0;

    @Override
    public void upsertDatabase(HiveDatabaseInfo database) {
      databases.put(database.getName(), database);
    }

    @Override
    public void deleteDatabase(String dbName) {
      databases.remove(dbName);
    }

    @Override
    public void upsertTable(HiveTableInfo table) {
      tables.put(table.getFullName(), table);
    }

    @Override
    public void alterTable(HiveTableInfo tableBefore, HiveTableInfo tableAfter) {
      tables.remove(tableBefore.getFullName());
      tables.put(tableAfter.getFullName(), tableAfter);
    }

    @Override
    public void deleteTable(String dbName, String tableName) {
      tables.remove(fullResourceName(dbName, tableName));
    }

    @Override
    public void upsertPartitions(Collection<HivePartitionInfo> newPartitions) {
      newPartitions.forEach(partition -> partitions.put(partition.getFullName(), partition));
    }

    @Override
    public void deletePartitions(String dbName, String tableName, Collection<String> partitionNames) {
      partitionNames.forEach(name -> partitions.remove(fullResourceName(dbName, tableName, name)));
    }

    @Override
    public void alterPartition(HivePartitionInfo partitionBefore, HivePartitionInfo partitionAfter) {
      partitions.remove(partitionBefore.getFullName());
      partitions.put(partitionAfter.getFullName(), partitionAfter);
    }

    @Override
    public void deleteAll() {
      databases.clear();
      tables.clear();
      partitions.clear();
    }

    @Override
    public <T> T execute(TransactionCallback<T> action) throws TransactionException {
      transactionsCount++;
      return action.doInTransaction(new SimpleTransactionStatus());
    }
  }
}
