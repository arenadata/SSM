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
import org.smartdata.hive.catalog.HiveDatabaseInfo;
import org.smartdata.hive.catalog.HiveDatabaseSearchRequest;
import org.smartdata.metastore.TestDaoBase;
import org.smartdata.metastore.queries.sort.HiveDatabaseSortField;

import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.smartdata.metastore.dao.HiveCatalogTestData.database;

public class TestHiveDatabaseDao extends TestDaoBase {
  private HiveDatabaseDao databaseDao;

  @Before
  public void initDao() {
    databaseDao = daoProvider.hiveDatabaseDao();
  }

  @Test
  public void testUpsertAndGetByName() {
    HiveDatabaseInfo database = database("db1")
        .catalogName("hive")
        .build();
    databaseDao.upsert(database);

    assertEquals(Optional.of(database), databaseDao.getByName("db1"));
    assertEquals(Optional.empty(), databaseDao.getByName("unknown"));

    databaseDao.upsert(database.toBuilder()
        .location("hdfs://ns1/new/db1.db")
        .build());

    HiveDatabaseInfo expectedDatabase = database.toBuilder()
        .location("hdfs://ns1/new/db1.db/")
        .build();
    assertEquals(Optional.of(expectedDatabase), databaseDao.getByName("db1"));
  }

  @Test
  public void testUpsertWithoutLocation() {
    HiveDatabaseInfo database = database("db1")
        .location(null)
        .build();
    databaseDao.upsert(database);

    assertEquals(Optional.of(database), databaseDao.getByName("db1"));
  }

  @Test
  public void testDelete() {
    databaseDao.upsert(database("db1").build());
    databaseDao.upsert(database("db2").build());

    databaseDao.delete("db1");
    // deletion of non-existent database shouldn't fail
    databaseDao.delete("unknown");

    assertEquals(Optional.empty(), databaseDao.getByName("db1"));
    assertTrue(databaseDao.getByName("db2").isPresent());
  }

  @Test
  public void testDeleteAll() throws Exception {
    databaseDao.upsert(database("db1").build());
    databaseDao.upsert(database("db2").build());

    databaseDao.deleteAll();

    assertTrue(databaseDao.search(HiveDatabaseSearchRequest.noFilters()).isEmpty());
  }

  @Test
  public void testSearch() {
    databaseDao.upsert(database("sales").build());
    databaseDao.upsert(database("sales_archive").build());
    databaseDao.upsert(database("marketing").build());

    SearchableTestSupport<HiveDatabaseSearchRequest, HiveDatabaseInfo, HiveDatabaseSortField, String>
        searchSupport = new SearchableTestSupport<>(
        databaseDao, HiveDatabaseSortField.NAME, HiveDatabaseInfo::getName);

    searchSupport.testSearch(HiveDatabaseSearchRequest.noFilters(),
        "marketing", "sales", "sales_archive");
    searchSupport.testSearch(HiveDatabaseSearchRequest.builder().nameLike("SALES").build(),
        "sales", "sales_archive");
    searchSupport.testSearch(HiveDatabaseSearchRequest.builder().nameLike("unknown").build());
  }
}
