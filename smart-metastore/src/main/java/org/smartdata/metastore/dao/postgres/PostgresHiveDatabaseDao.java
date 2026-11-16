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

import org.smartdata.hive.catalog.HiveDatabaseInfo;
import org.smartdata.hive.catalog.HiveDatabaseSearchRequest;
import org.smartdata.metastore.SearchableAbstractDao;
import org.smartdata.metastore.dao.HiveDatabaseDao;
import org.smartdata.metastore.queries.MetastoreQuery;
import org.smartdata.metastore.queries.sort.HiveDatabaseSortField;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.smartdata.hive.catalog.HiveCatalogDao.DATABASES_TABLE_NAME;
import static org.smartdata.metastore.queries.MetastoreQuery.selectAll;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.equal;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.likeCaseInsensitive;
import static org.smartdata.utils.PathUtil.addPathSeparator;

public class PostgresHiveDatabaseDao
    extends SearchableAbstractDao<HiveDatabaseSearchRequest, HiveDatabaseInfo, HiveDatabaseSortField>
    implements HiveDatabaseDao {

  private static final String NAME_FIELD = "name";
  private static final String CATALOG_NAME_FIELD = "catalog_name";
  private static final String LOCATION_FIELD = "location";

  private final PostgresInsertSupport insertSupport;

  public PostgresHiveDatabaseDao(
      DataSource dataSource, PlatformTransactionManager transactionManager) {
    super(dataSource, transactionManager, DATABASES_TABLE_NAME);
    this.insertSupport = new PostgresInsertSupport(dataSource, DATABASES_TABLE_NAME);
  }

  @Override
  public Optional<HiveDatabaseInfo> getByName(String name) {
    MetastoreQuery query = selectAll()
        .from(tableName)
        .where(equal(NAME_FIELD, name));
    return executeSingle(query);
  }

  @Override
  public void upsert(HiveDatabaseInfo database) {
    insertSupport.upsert(toMap(database), NAME_FIELD);
  }

  @Override
  public void delete(String name) {
    jdbcTemplate.update("DELETE FROM " + tableName + " WHERE " + NAME_FIELD + " = ?", name);
  }

  @Override
  public void deleteAll() {
    jdbcTemplate.update("DELETE FROM " + tableName);
  }

  @Override
  protected MetastoreQuery searchQuery(HiveDatabaseSearchRequest searchRequest) {
    return selectAll()
        .from(tableName)
        .where(likeCaseInsensitive(NAME_FIELD, searchRequest.getNameLike()));
  }

  @Override
  protected HiveDatabaseInfo mapRow(ResultSet resultSet, int rowNum) throws SQLException {
    return HiveDatabaseInfo.builder()
        .name(resultSet.getString(NAME_FIELD))
        .catalogName(resultSet.getString(CATALOG_NAME_FIELD))
        .location(resultSet.getString(LOCATION_FIELD))
        .build();
  }

  private Map<String, Object> toMap(HiveDatabaseInfo database) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put(NAME_FIELD, database.getName());
    parameters.put(CATALOG_NAME_FIELD, database.getCatalogName());
    parameters.put(LOCATION_FIELD, addPathSeparator(database.getLocation()));
    return parameters;
  }
}
