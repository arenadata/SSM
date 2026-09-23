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
package org.smartdata.server.engine;

import lombok.extern.slf4j.Slf4j;
import org.smartdata.exception.NotFoundException;
import org.smartdata.hive.catalog.HiveDatabaseInfo;
import org.smartdata.hive.catalog.HiveDatabaseSearchRequest;
import org.smartdata.hive.catalog.HiveTableInfo;
import org.smartdata.hive.catalog.HiveTableSearchRequest;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.dao.HiveDatabaseDao;
import org.smartdata.metastore.dao.HiveTableDao;
import org.smartdata.metastore.dao.Searchable;
import org.smartdata.metastore.dao.SearchableService;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.HiveDatabaseSortField;
import org.smartdata.metastore.queries.sort.HiveTableSortField;

import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.Callable;

import static org.smartdata.hive.fetch.HiveNotificationEvent.fullResourceName;
import static org.smartdata.metastore.utils.MetaStoreUtils.logAndBuildMetastoreException;

/**
 * Provides access to the SSM copy of the source Hive catalog.
 */
@Slf4j
public class HiveCatalogManager {
  private final HiveDatabaseDao databaseDao;
  private final HiveTableDao tableDao;
  private final Searchable<HiveDatabaseSearchRequest, HiveDatabaseInfo, HiveDatabaseSortField>
      databasesSearchService;
  private final Searchable<HiveTableSearchRequest, HiveTableInfo, HiveTableSortField>
      tablesSearchService;

  public HiveCatalogManager(MetaStore metaStore) {
    this(metaStore.hiveDatabaseDao(), metaStore.hiveTableDao());
  }

  public HiveCatalogManager(HiveDatabaseDao databaseDao, HiveTableDao tableDao) {
    this.databaseDao = databaseDao;
    this.tableDao = tableDao;
    this.databasesSearchService = new SearchableService<>(databaseDao, "Hive databases");
    this.tablesSearchService = new SearchableService<>(tableDao, "Hive tables");
  }

  public SearchResult<HiveDatabaseInfo> searchDatabases(
      HiveDatabaseSearchRequest searchRequest,
      PageRequest<HiveDatabaseSortField> pageRequest) throws IOException {
    return databasesSearchService.search(searchRequest, pageRequest);
  }

  public HiveDatabaseInfo getDatabase(String name) throws IOException {
    return getEntity(() -> databaseDao.getByName(name), "Hive database", name);
  }

  public SearchResult<HiveTableInfo> searchTables(
      HiveTableSearchRequest searchRequest,
      PageRequest<HiveTableSortField> pageRequest) throws IOException {
    return tablesSearchService.search(searchRequest, pageRequest);
  }

  public HiveTableInfo getTable(String dbName, String tableName) throws IOException {
    return getEntity(() -> tableDao.get(dbName, tableName),
        "Hive table", fullResourceName(dbName, tableName));
  }

  private <T> T getEntity(
      Callable<Optional<T>> entitySupplier,
      String entityType,
      String name) throws IOException {
    Optional<T> entity;
    try {
      entity = entitySupplier.call();
    } catch (Exception exception) {
      throw logAndBuildMetastoreException(log, "Error fetching " + entityType + " " + name, exception);
    }

    return entity.orElseThrow(
        () -> NotFoundException.forIdentifiableEntity(entityType, name));
  }
}
