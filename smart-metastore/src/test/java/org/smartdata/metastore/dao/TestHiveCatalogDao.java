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

import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.hive.catalog.HiveCatalogDao;
import org.smartdata.hive.catalog.HiveDatabaseSearchRequest;
import org.smartdata.hive.catalog.HivePartitionInfo;
import org.smartdata.hive.catalog.HiveTableInfo;
import org.smartdata.hive.catalog.HiveTableSearchRequest;
import org.smartdata.metastore.TestDaoBase;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.smartdata.metastore.dao.HiveCatalogTestData.database;
import static org.smartdata.metastore.dao.HiveCatalogTestData.partition;
import static org.smartdata.metastore.dao.HiveCatalogTestData.table;

/**
 * Tests of the catalog operations, which affect several catalog entities.
 * Operations of the particular entities are tested in the corresponding DAO tests.
 */
public class TestHiveCatalogDao extends TestDaoBase {
  private HiveDatabaseDao databaseDao;
  private HiveTableDao tableDao;
  private HivePartitionDao partitionDao;
  private HiveCatalogDao catalogDao;

  @Before
  public void initDaos() {
    databaseDao = daoProvider.hiveDatabaseDao();
    tableDao = daoProvider.hiveTableDao();
    partitionDao = daoProvider.hivePartitionDao();
    catalogDao = daoProvider.hiveCatalogDao();
  }

  @Test
  public void testDeleteTableWithPartitions() {
    catalogDao.upsertTable(table("db1", "sales").build());
    catalogDao.upsertTable(table("db1", "clients").build());
    catalogDao.upsertPartitions(Arrays.asList(
        partition("db1", "sales", "year=2025").build(),
        partition("db1", "clients", "country=us").build()));

    catalogDao.deleteTable("db1", "sales");

    assertEquals(Optional.empty(), tableDao.get("db1", "sales"));
    assertTrue(partitionDao.getByTable("db1", "sales").isEmpty());
    assertTrue(tableDao.get("db1", "clients").isPresent());
    assertEquals(1, partitionDao.getByTable("db1", "clients").size());
  }

  @Test
  public void testDeleteDatabaseWithTablesAndPartitions() {
    catalogDao.upsertDatabase(database("db1").build());
    catalogDao.upsertDatabase(database("db2").build());
    catalogDao.upsertTable(table("db1", "sales").build());
    catalogDao.upsertTable(table("db2", "sales").build());
    catalogDao.upsertPartitions(Arrays.asList(
        partition("db1", "sales", "year=2025").build(),
        partition("db2", "sales", "year=2025").build()));

    catalogDao.deleteDatabase("db1");

    assertEquals(Optional.empty(), databaseDao.getByName("db1"));
    assertEquals(Optional.empty(), tableDao.get("db1", "sales"));
    assertTrue(partitionDao.getByTable("db1", "sales").isEmpty());
    assertTrue(databaseDao.getByName("db2").isPresent());
    assertTrue(tableDao.get("db2", "sales").isPresent());
    assertEquals(1, partitionDao.getByTable("db2", "sales").size());
  }

  @Test
  public void testDeleteAll() throws Exception {
    catalogDao.upsertDatabase(database("db1").build());
    catalogDao.upsertTable(table("db1", "sales").build());
    catalogDao.upsertPartitions(Collections.singletonList(
        partition("db1", "sales", "year=2025").build()));

    catalogDao.deleteAll();

    assertTrue(databaseDao.search(HiveDatabaseSearchRequest.noFilters()).isEmpty());
    assertTrue(tableDao.search(HiveTableSearchRequest.noFilters()).isEmpty());
    assertTrue(partitionDao.getByTable("db1", "sales").isEmpty());
  }

  @Test
  public void testAlterTableRenameWithDataMove() {
    String oldLocation = "hdfs://ns1/warehouse/db1.db/sales/";
    String newLocation = "hdfs://ns1/warehouse/db1.db/revenue/";
    HiveTableInfo tableBefore = table("db1", "sales").location(oldLocation).build();
    HiveTableInfo tableAfter = table("db1", "revenue").location(newLocation).build();

    catalogDao.upsertTable(tableBefore);
    catalogDao.upsertPartitions(Arrays.asList(
        partition("db1", "sales", "year=2025").location(oldLocation + "year=2025/").build(),
        partition("db1", "sales", "year=2024").location("hdfs://ns1/external/2024/").build()));

    catalogDao.alterTable(tableBefore, tableAfter);

    assertEquals(Optional.empty(), tableDao.get("db1", "sales"));
    assertEquals(Optional.of(tableAfter), tableDao.get("db1", "revenue"));
    assertTrue(partitionDao.getByTable("db1", "sales").isEmpty());
    // only partitions inside the table location are moved along with the table data
    assertEquals(
        Arrays.asList("hdfs://ns1/external/2024/", newLocation + "year=2025/"),
        locations(partitionDao.getByTable("db1", "revenue")));
  }

  @Test
  public void testAlterTableRenameWithoutDataMove() {
    String location = "hdfs://ns1/external/sales/";
    HiveTableInfo tableBefore = table("db1", "sales").location(location).build();
    HiveTableInfo tableAfter = table("db2", "sales").location(location).build();
    HivePartitionInfo partition = partition("db1", "sales", "year=2025")
        .location(location + "year=2025/")
        .build();

    catalogDao.upsertTable(tableBefore);
    catalogDao.upsertPartitions(Collections.singletonList(partition));

    catalogDao.alterTable(tableBefore, tableAfter);

    assertEquals(Optional.empty(), tableDao.get("db1", "sales"));
    assertEquals(Optional.of(tableAfter), tableDao.get("db2", "sales"));
    assertEquals(
        Collections.singletonList(partition.toBuilder().dbName("db2").build()),
        partitionDao.getByTable("db2", "sales"));
  }

  @Test
  public void testAlterTableLocationWithoutRename() {
    String oldLocation = "hdfs://ns1/warehouse/db1.db/sales/";
    HiveTableInfo tableBefore = table("db1", "sales").location(oldLocation).build();
    HiveTableInfo tableAfter = table("db1", "sales").location("hdfs://ns1/data/sales_v2/").build();
    HivePartitionInfo partition = partition("db1", "sales", "year=2025")
        .location(oldLocation + "year=2025/")
        .build();

    catalogDao.upsertTable(tableBefore);
    catalogDao.upsertPartitions(Collections.singletonList(partition));

    catalogDao.alterTable(tableBefore, tableAfter);

    assertEquals(Optional.of(tableAfter), tableDao.get("db1", "sales"));
    // HMS doesn't move partitions on the table location change without renaming
    assertEquals(Collections.singletonList(partition), partitionDao.getByTable("db1", "sales"));
  }

  @Test
  public void testAlterPartition() {
    HivePartitionInfo partition2025 = partition("db1", "sales", "year=2025").build();
    HivePartitionInfo partition2024 = partition("db1", "sales", "year=2024").build();
    catalogDao.upsertPartitions(Arrays.asList(partition2025, partition2024));

    // location change
    HivePartitionInfo movedPartition = partition2025.toBuilder().location("hdfs://ns1/moved/").build();
    catalogDao.alterPartition(partition2025, movedPartition);

    assertEquals(Arrays.asList(partition2024, movedPartition),
        partitionDao.getByTable("db1", "sales"));

    // rename by changing the partition values
    HivePartitionInfo renamedPartition = movedPartition.toBuilder().name("year=2026").build();
    catalogDao.alterPartition(movedPartition, renamedPartition);

    assertEquals(Arrays.asList(partition2024, renamedPartition),
        partitionDao.getByTable("db1", "sales"));
  }

  @Test
  public void testFailedNestedTransactionKeepsOuterTransactionUsable() {
    TransactionTemplate outerTransaction = new TransactionTemplate(metaStore.transactionManager());

    outerTransaction.executeWithoutResult(status -> {
      catalogDao.upsertDatabase(database("db1").build());

      // the name is longer than the column size, so the insert fails on the DB side
      String tooLongName = StringUtils.repeat("a", 300);
      assertThrows(Exception.class, () -> catalogDao.executeWithoutResult(nestedStatus ->
          catalogDao.upsertDatabase(database(tooLongName).build())));

      // the outer transaction should be still usable
      catalogDao.upsertDatabase(database("db2").build());
    });

    assertTrue(databaseDao.getByName("db1").isPresent());
    assertTrue(databaseDao.getByName("db2").isPresent());
  }

  private static List<String> locations(List<HivePartitionInfo> partitions) {
    return partitions.stream()
        .map(HivePartitionInfo::getLocation)
        .collect(Collectors.toList());
  }
}
