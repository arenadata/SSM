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
import org.smartdata.hive.catalog.HiveCatalogDao;
import org.smartdata.hive.catalog.HiveCatalogStateDao;
import org.smartdata.metastore.TestDaoBase;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.smartdata.metastore.dao.HiveCatalogTestData.database;

public class TestHiveCatalogStateDao extends TestDaoBase {
  private HiveCatalogStateDao catalogStateDao;
  private HiveCatalogDao catalogDao;
  private HiveDatabaseDao databaseDao;

  @Before
  public void initDaos() {
    catalogStateDao = daoProvider.hiveCatalogStateDao();
    catalogDao = daoProvider.hiveCatalogDao();
    databaseDao = daoProvider.hiveDatabaseDao();
  }

  @Test
  public void testMarkInitialized() {
    assertFalse(catalogStateDao.isInitialized());

    catalogStateDao.markInitialized();
    assertTrue(catalogStateDao.isInitialized());

    // marking the initialized catalog shouldn't fail
    catalogStateDao.markInitialized();
    assertTrue(catalogStateDao.isInitialized());
  }

  @Test
  public void testInitializedStateIsRolledBackWithCatalog() {
    TransactionTemplate outerTransaction = new TransactionTemplate(metaStore.transactionManager());

    assertThrows(IllegalStateException.class, () -> outerTransaction.executeWithoutResult(status -> {
      catalogDao.upsertDatabase(database("db1").build());
      catalogStateDao.markInitialized();
      throw new IllegalStateException("Catalog filling failure");
    }));

    assertFalse(catalogStateDao.isInitialized());
    assertEquals(Optional.empty(), databaseDao.getByName("db1"));
  }
}
