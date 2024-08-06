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
package org.smartdata.metastore.dao.accesscount;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.dao.AbstractDao;
import org.smartdata.metastore.dao.CacheFileDao;
import org.smartdata.metastore.model.AccessCountTable;
import org.smartdata.metastore.model.AggregatedAccessCounts;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.FileAccessInfoSortField;
import org.smartdata.metastore.transaction.TransactionRunner;
import org.smartdata.model.FileAccessInfo;
import org.smartdata.model.request.FileAccessInfoSearchRequest;

import javax.sql.DataSource;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class DbAccessCountTableManager
    extends AbstractDao implements AccessCountTableHandler {
  static final Logger LOG = LoggerFactory.getLogger(DbAccessCountTableManager.class);

  private final TransactionRunner transactionRunner;
  private final AccessCountTableDao accessCountTableDao;
  private final AccessCountEventDao accessCountEventDao;
  private final CacheFileDao cacheFileDao;

  public DbAccessCountTableManager(MetaStore metastore) {
    this(
        metastore.getDataSource(),
        new TransactionRunner(metastore.transactionManager()),
        metastore.accessCountTableDao(),
        metastore.accessCountEventDao(),
        metastore.cacheFileDao()
    );
  }

  public DbAccessCountTableManager(
      DataSource dataSource,
      TransactionRunner transactionRunner,
      AccessCountTableDao accessCountTableDao,
      AccessCountEventDao accessCountEventDao,
      CacheFileDao cacheFileDao) {
    super(dataSource, AccessCountTableDao.TABLE_NAME);
    this.accessCountTableDao = accessCountTableDao;
    this.accessCountEventDao = accessCountEventDao;
    this.cacheFileDao = cacheFileDao;
    this.transactionRunner = transactionRunner;
  }

  @Override
  public void aggregate(
      AccessCountTable destinationTable,
      List<AccessCountTable> tablesToAggregate) throws MetaStoreException {
    if (tablesToAggregate.isEmpty()) {
      return;
    }

    transactionRunner.inTransaction(() -> {
      createTable(destinationTable);
      aggregateTablesInternal(destinationTable, tablesToAggregate);
    });
  }

  public void createTable(AccessCountTable table) throws MetaStoreException {
    transactionRunner.inTransaction(() -> {
      createAccessCountTable(table);
      accessCountTableDao.insert(table);
    });
  }

  public void createPartialTable(AccessCountTable dest, AccessCountTable source)
      throws MetaStoreException {
    transactionRunner.inTransaction(() -> {
      createAccessCountTable(dest);
      fillPartialTable(dest, source);
    });
  }

  public SearchResult<FileAccessInfo> getFileAccessInfoList(
      FileAccessInfoSearchRequest searchRequest,
      PageRequest<FileAccessInfoSortField> pageRequest) {
    return accessCountEventDao.search(searchRequest, pageRequest);
  }

  public List<FileAccessInfo> getFileAccessInfoList(FileAccessInfoSearchRequest searchRequest) {
    return accessCountEventDao.search(searchRequest);
  }

  @Override
  public void dropTable(AccessCountTable accessCountTable) throws MetaStoreException {
    transactionRunner.inTransaction(() -> {
      dropDbTable(accessCountTable);
      accessCountTableDao.delete(accessCountTable);
    });
  }

  public void handleAggregatedEvents(
      AccessCountTable table,
      Collection<AggregatedAccessCounts> accessCounts) throws MetaStoreException {
    if (accessCounts.isEmpty()) {
      return;
    }

    transactionRunner.inTransaction(() -> {
      insertAccessCountsToMetastore(table, accessCounts);
      updateCachedFilesInMetastore(accessCounts);
    });
  }

  public List<AccessCountTable> getTables() {
    return accessCountTableDao.getAllSortedTables()
        .stream()
        .filter(this::isValid)
        .collect(Collectors.toList());
  }

  private boolean isValid(AccessCountTable table) {
    try {
      accessCountEventDao.validate(table);
      return true;
    } catch (MetaStoreException exception) {
      LOG.error("Can't recover table {}, dropping it", table, exception);
      dropDbTable(table);
      return false;
    }
  }

  private void fillPartialTable(AccessCountTable dest, AccessCountTable source) {
    String statement =
        "INSERT INTO " + dest.getTableName()
            + " SELECT src.fid, ROUND(src.count * " + dest.intervalRatio(source)
            + "), src.last_accessed_time"
            + " FROM " + source.getTableName() + " as src"
            + " WHERE src.last_accessed_time >= " + source.getStartTime();

    jdbcTemplate.execute(statement);
  }

  private void aggregateTablesInternal(AccessCountTable destination,
                                       List<AccessCountTable> sources) {
    String query = "INSERT INTO " + destination.getTableName()
        + " SELECT aggregated_events.fid, "
        + "aggregated_events.count, "
        + "aggregated_events.last_accessed_time "
        + "FROM ("
        + "SELECT fid, SUM(count) AS count, MAX(last_accessed_time) as last_accessed_time "
        + "FROM (" + AccessCountEventDao.unionTablesQuery(sources) + ") as union_events "
        + "GROUP BY fid) AS aggregated_events "
        + "JOIN file ON file.fid = aggregated_events.fid;";

    LOG.debug("Executing access count tables aggregation: {}", query);
    jdbcTemplate.execute(query);
  }

  private void createAccessCountTable(AccessCountTable table) {
    String createStatement = "CREATE TABLE IF NOT EXISTS " + table.getTableName() + "("
        + "fid BIGINT NOT NULL, "
        + "count INTEGER NOT NULL, "
        + "last_accessed_time BIGINT NOT NULL)";

    jdbcTemplate.execute(createStatement);
  }

  private void dropDbTable(AccessCountTable accessCountTable) {
    String sql = "DROP TABLE IF EXISTS " + accessCountTable.getTableName();
    jdbcTemplate.execute(sql);
  }

  private void insertAccessCountsToMetastore(
      AccessCountTable table, Collection<AggregatedAccessCounts> accessCounts) {
    try {
      accessCountEventDao.insert(table, accessCounts);
      LOG.debug("Inserted values {} to access count table {}", accessCounts, table);
    } catch (Exception e) {
      LOG.error("Error inserting access counts {} to table {}", accessCounts, table, e);
    }
  }

  private void updateCachedFilesInMetastore(Collection<AggregatedAccessCounts> accessCounts) {
    try {
      cacheFileDao.update(accessCounts);
    } catch (Exception e) {
      LOG.error("Error updating cached files {}", accessCounts, e);
    }
  }
}
