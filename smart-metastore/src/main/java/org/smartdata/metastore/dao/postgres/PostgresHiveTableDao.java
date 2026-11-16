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
package org.smartdata.metastore.dao.postgres;

import org.smartdata.hive.catalog.HiveTableInfo;
import org.smartdata.hive.catalog.HiveTableSearchRequest;
import org.smartdata.metastore.SearchableAbstractDao;
import org.smartdata.metastore.dao.HiveTableDao;
import org.smartdata.metastore.queries.MetastoreQuery;
import org.smartdata.metastore.queries.sort.HiveTableSortField;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.smartdata.hive.catalog.HiveCatalogDao.TABLES_TABLE_NAME;
import static org.smartdata.metastore.queries.MetastoreQuery.selectAll;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.equal;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.in;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.likeCaseInsensitive;
import static org.smartdata.utils.PathUtil.addPathSeparator;

public class PostgresHiveTableDao
    extends SearchableAbstractDao<HiveTableSearchRequest, HiveTableInfo, HiveTableSortField>
    implements HiveTableDao {

  private static final String DB_NAME_FIELD = "db_name";
  private static final String NAME_FIELD = "name";
  private static final String CATALOG_NAME_FIELD = "catalog_name";
  private static final String LOCATION_FIELD = "location";

  private static final String PRIMARY_KEY_FIELDS = DB_NAME_FIELD + ", " + NAME_FIELD;

  private final PostgresInsertSupport insertSupport;

  public PostgresHiveTableDao(
      DataSource dataSource, PlatformTransactionManager transactionManager) {
    super(dataSource, transactionManager, TABLES_TABLE_NAME);
    this.insertSupport = new PostgresInsertSupport(dataSource, TABLES_TABLE_NAME);
  }

  @Override
  public Optional<HiveTableInfo> get(String dbName, String name) {
    MetastoreQuery query = selectAll()
        .from(tableName)
        .where(
            equal(DB_NAME_FIELD, dbName),
            equal(NAME_FIELD, name)
        );
    return executeSingle(query);
  }

  @Override
  public void upsert(HiveTableInfo table) {
    insertSupport.upsert(toMap(table), PRIMARY_KEY_FIELDS);
  }

  @Override
  public void delete(String dbName, String name) {
    jdbcTemplate.update("DELETE FROM " + tableName
        + " WHERE " + DB_NAME_FIELD + " = ? AND " + NAME_FIELD + " = ?", dbName, name);
  }

  @Override
  public void deleteByDbName(String dbName) {
    jdbcTemplate.update("DELETE FROM " + tableName + " WHERE " + DB_NAME_FIELD + " = ?", dbName);
  }

  @Override
  public void deleteAll() {
    jdbcTemplate.update("DELETE FROM " + tableName);
  }

  @Override
  protected MetastoreQuery searchQuery(HiveTableSearchRequest searchRequest) {
    return selectAll()
        .from(tableName)
        .where(
            in(DB_NAME_FIELD, searchRequest.getDbNames()),
            likeCaseInsensitive(NAME_FIELD, searchRequest.getNameLike())
        );
  }

  @Override
  protected HiveTableInfo mapRow(ResultSet resultSet, int rowNum) throws SQLException {
    return HiveTableInfo.builder()
        .dbName(resultSet.getString(DB_NAME_FIELD))
        .name(resultSet.getString(NAME_FIELD))
        .catalogName(resultSet.getString(CATALOG_NAME_FIELD))
        .location(resultSet.getString(LOCATION_FIELD))
        .build();
  }

  private Map<String, Object> toMap(HiveTableInfo table) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put(DB_NAME_FIELD, table.getDbName());
    parameters.put(NAME_FIELD, table.getName());
    parameters.put(CATALOG_NAME_FIELD, table.getCatalogName());
    parameters.put(LOCATION_FIELD, addPathSeparator(table.getLocation()));
    return parameters;
  }
}
