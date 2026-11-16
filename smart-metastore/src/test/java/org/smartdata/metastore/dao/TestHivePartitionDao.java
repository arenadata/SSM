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

import org.junit.Before;
import org.junit.Test;
import org.smartdata.hive.catalog.HivePartitionInfo;
import org.smartdata.metastore.TestDaoBase;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.smartdata.metastore.dao.HiveCatalogTestData.partition;

public class TestHivePartitionDao extends TestDaoBase {
  private HivePartitionDao partitionDao;

  @Before
  public void initDao() {
    partitionDao = daoProvider.hivePartitionDao();
  }

  @Test
  public void testUpsertAndGetByTable() {
    partitionDao.upsert(Arrays.asList(
        partition("db1", "sales", "year=2025").build(),
        partition("db1", "sales", "year=2024").build(),
        partition("db1", "clients", "country=us").build(),
        partition("db2", "sales", "year=2023").build()));

    // update existing partition and add a new one
    partitionDao.upsert(Arrays.asList(
        partition("db1", "sales", "year=2025").location("hdfs://ns1/moved").build(),
        partition("db1", "sales", "year=2022").build()));
    HivePartitionInfo movedPartition = partition("db1", "sales", "year=2025")
        .location("hdfs://ns1/moved/")
        .build();

    // upserting of empty collection shouldn't fail
    partitionDao.upsert(Collections.emptyList());

    // partitions are ordered by name
    assertEquals(
        Arrays.asList(
            partition("db1", "sales", "year=2022").build(),
            partition("db1", "sales", "year=2024").build(),
            movedPartition),
        partitionDao.getByTable("db1", "sales"));
    assertEquals(Collections.singletonList(partition("db2", "sales", "year=2023").build()),
        partitionDao.getByTable("db2", "sales"));
    assertTrue(partitionDao.getByTable("db1", "unknown").isEmpty());
  }

  @Test
  public void testDelete() {
    partitionDao.upsert(Arrays.asList(
        partition("db1", "sales", "year=2025").build(),
        partition("db1", "sales", "year=2024").build(),
        partition("db1", "sales", "year=2023").build(),
        partition("db1", "clients", "country=us").build()));

    partitionDao.delete("db1", "sales", Arrays.asList("year=2025", "year=2023", "unknown"));
    // deletion of empty collection shouldn't fail
    partitionDao.delete("db1", "sales", Collections.emptyList());

    assertEquals(Collections.singletonList(partition("db1", "sales", "year=2024").build()),
        partitionDao.getByTable("db1", "sales"));
    assertEquals(1, partitionDao.getByTable("db1", "clients").size());
  }

  @Test
  public void testDeleteByTableAndDbName() {
    partitionDao.upsert(Arrays.asList(
        partition("db1", "sales", "year=2025").build(),
        partition("db1", "clients", "country=us").build(),
        partition("db2", "sales", "year=2025").build()));

    partitionDao.deleteByTable("db1", "sales");

    assertTrue(partitionDao.getByTable("db1", "sales").isEmpty());
    assertEquals(1, partitionDao.getByTable("db1", "clients").size());

    partitionDao.deleteByDbName("db1");

    assertTrue(partitionDao.getByTable("db1", "clients").isEmpty());
    assertEquals(1, partitionDao.getByTable("db2", "sales").size());

    partitionDao.deleteAll();

    assertTrue(partitionDao.getByTable("db2", "sales").isEmpty());
  }

  @Test
  public void testRenameTable() {
    HivePartitionInfo partition = partition("db1", "sales", "year=2025").build();
    partitionDao.upsert(Arrays.asList(
        partition,
        partition("db1", "clients", "country=us").build()));

    partitionDao.renameTable("db1", "sales", "db2", "revenue");

    assertTrue(partitionDao.getByTable("db1", "sales").isEmpty());
    // only the table name is changed, not the location
    assertEquals(
        Collections.singletonList(partition.toBuilder()
            .dbName("db2")
            .tableName("revenue")
            .build()),
        partitionDao.getByTable("db2", "revenue"));
    assertEquals(1, partitionDao.getByTable("db1", "clients").size());
  }

  @Test
  public void testReplaceLocation() {
    String oldLocation = "hdfs://ns1/warehouse/db1.db/sales/";
    String newLocation = "hdfs://ns1/warehouse/db1.db/revenue/";
    partitionDao.upsert(Arrays.asList(
        partition("db1", "sales", "year=2025").location(oldLocation + "year=2025/").build(),
        partition("db1", "sales", "year=2024").location(oldLocation).build(),
        partition("db1", "sales", "year=2023").location("hdfs://ns1/external/2023/").build(),
        // the same prefix, but outside the table location
        partition("db1", "sales", "year=2022")
            .location("hdfs://ns1/warehouse/db1.db/sales_backup/2022/")
            .build(),
        // the same location, but another table
        partition("db1", "clients", "country=us").location(oldLocation + "us/").build()));

    // locations without the trailing path separator should be handled as well
    partitionDao.replaceLocation("db1", "sales",
        "hdfs://ns1/warehouse/db1.db/sales", "hdfs://ns1/warehouse/db1.db/revenue");

    assertEquals(
        Arrays.asList(
            "hdfs://ns1/warehouse/db1.db/sales_backup/2022/",
            "hdfs://ns1/external/2023/",
            newLocation,
            newLocation + "year=2025/"),
        locations(partitionDao.getByTable("db1", "sales")));
    assertEquals(Collections.singletonList(oldLocation + "us/"),
        locations(partitionDao.getByTable("db1", "clients")));
  }

  private static List<String> locations(List<HivePartitionInfo> partitions) {
    return partitions.stream()
        .map(HivePartitionInfo::getLocation)
        .collect(Collectors.toList());
  }
}
