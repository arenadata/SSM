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
import org.smartdata.hive.catalog.HiveTableInfo;
import org.smartdata.hive.catalog.HiveTableSearchRequest;
import org.smartdata.metastore.TestDaoBase;
import org.smartdata.metastore.queries.sort.HiveTableSortField;

import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.smartdata.metastore.dao.HiveCatalogTestData.table;

public class TestHiveTableDao extends TestDaoBase {
  private HiveTableDao tableDao;

  @Before
  public void initDao() {
    tableDao = daoProvider.hiveTableDao();
  }

  @Test
  public void testUpsertAndGet() {
    HiveTableInfo table = table("db1", "tbl1")
        .catalogName("hive")
        .build();
    tableDao.upsert(table);

    assertEquals(Optional.of(table), tableDao.get("db1", "tbl1"));
    assertEquals(Optional.empty(), tableDao.get("db1", "unknown"));
    assertEquals(Optional.empty(), tableDao.get("db2", "tbl1"));

    tableDao.upsert(table.toBuilder()
        .location("hdfs://ns1/external/tbl1")
        .build());

    HiveTableInfo expectedTable = table.toBuilder()
        .location("hdfs://ns1/external/tbl1/")
        .build();
    assertEquals(Optional.of(expectedTable), tableDao.get("db1", "tbl1"));
  }

  @Test
  public void testDelete() {
    tableDao.upsert(table("db1", "tbl1").build());
    tableDao.upsert(table("db1", "tbl2").build());
    tableDao.upsert(table("db2", "tbl1").build());

    tableDao.delete("db1", "tbl1");
    // deletion of non-existent table shouldn't fail
    tableDao.delete("db1", "unknown");

    assertEquals(Optional.empty(), tableDao.get("db1", "tbl1"));
    assertTrue(tableDao.get("db1", "tbl2").isPresent());
    assertTrue(tableDao.get("db2", "tbl1").isPresent());
  }

  @Test
  public void testDeleteByDbName() {
    tableDao.upsert(table("db1", "tbl1").build());
    tableDao.upsert(table("db1", "tbl2").build());
    tableDao.upsert(table("db2", "tbl1").build());

    tableDao.deleteByDbName("db1");

    assertEquals(Optional.empty(), tableDao.get("db1", "tbl1"));
    assertEquals(Optional.empty(), tableDao.get("db1", "tbl2"));
    assertTrue(tableDao.get("db2", "tbl1").isPresent());
  }

  @Test
  public void testDeleteAll() throws Exception {
    tableDao.upsert(table("db1", "tbl1").build());
    tableDao.upsert(table("db2", "tbl1").build());

    tableDao.deleteAll();

    assertTrue(tableDao.search(HiveTableSearchRequest.noFilters()).isEmpty());
  }

  @Test
  public void testSearch() {
    tableDao.upsert(table("db1", "orders").build());
    tableDao.upsert(table("db1", "orders_archive").build());
    tableDao.upsert(table("db2", "clients").build());
    tableDao.upsert(table("db2", "payments").build());
    tableDao.upsert(table("db3", "events").build());

    SearchableTestSupport<HiveTableSearchRequest, HiveTableInfo, HiveTableSortField, String>
        searchSupport = new SearchableTestSupport<>(
        tableDao, HiveTableSortField.NAME, HiveTableInfo::getFullName);

    searchSupport.testSearch(HiveTableSearchRequest.noFilters(),
        "db2.clients", "db3.events", "db1.orders", "db1.orders_archive", "db2.payments");
    searchSupport.testSearch(HiveTableSearchRequest.builder().dbName("db2").build(),
        "db2.clients", "db2.payments");
    searchSupport.testSearch(HiveTableSearchRequest.builder().dbName("db1").dbName("db2").build(),
        "db2.clients", "db1.orders", "db1.orders_archive", "db2.payments");
    searchSupport.testSearch(HiveTableSearchRequest.builder().dbName("unknown").build());
    searchSupport.testSearch(HiveTableSearchRequest.builder().nameLike("ORDERS").build(),
        "db1.orders", "db1.orders_archive");
    searchSupport.testSearch(HiveTableSearchRequest.builder()
            .dbName("db1")
            .nameLike("archive")
            .build(),
        "db1.orders_archive");
  }
}
