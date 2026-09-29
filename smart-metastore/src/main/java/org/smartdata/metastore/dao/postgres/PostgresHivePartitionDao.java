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

import org.smartdata.hive.catalog.HivePartitionInfo;
import org.smartdata.metastore.dao.AbstractDao;
import org.smartdata.metastore.dao.HivePartitionDao;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.smartdata.hive.catalog.HiveCatalogDao.PARTITIONS_TABLE_NAME;
import static org.smartdata.utils.PathUtil.addPathSeparator;

public class PostgresHivePartitionDao extends AbstractDao implements HivePartitionDao {

  private static final String DB_NAME_FIELD = "db_name";
  private static final String TABLE_NAME_FIELD = "table_name";
  private static final String NAME_FIELD = "name";
  private static final String LOCATION_FIELD = "location";

  private static final String PRIMARY_KEY_FIELDS =
      DB_NAME_FIELD + ", " + TABLE_NAME_FIELD + ", " + NAME_FIELD;

  private final PostgresInsertSupport insertSupport;
  private final NamedParameterJdbcTemplate namedJdbcTemplate;

  public PostgresHivePartitionDao(DataSource dataSource) {
    super(dataSource, PARTITIONS_TABLE_NAME);
    this.insertSupport = new PostgresInsertSupport(dataSource, PARTITIONS_TABLE_NAME);
    this.namedJdbcTemplate = new NamedParameterJdbcTemplate(dataSource);
  }

  @Override
  public List<HivePartitionInfo> getByTable(String dbName, String tableName) {
    return jdbcTemplate.query("SELECT * FROM " + this.tableName
            + " WHERE " + DB_NAME_FIELD + " = ? AND " + TABLE_NAME_FIELD + " = ?"
            + " ORDER BY " + NAME_FIELD,
        this::mapRow, dbName, tableName);
  }

  @Override
  public void upsert(Collection<HivePartitionInfo> partitions) {
    insertSupport.batchUpsert(partitions, this::toMap, PRIMARY_KEY_FIELDS);
  }

  @Override
  public void delete(String dbName, String tableName, Collection<String> partitionNames) {
    List<Object[]> arguments = partitionNames.stream()
        .map(partitionName -> new Object[]{dbName, tableName, partitionName})
        .collect(Collectors.toList());

    jdbcTemplate.batchUpdate("DELETE FROM " + this.tableName
        + " WHERE " + DB_NAME_FIELD + " = ? AND " + TABLE_NAME_FIELD + " = ?"
        + " AND " + NAME_FIELD + " = ?", arguments);
  }

  @Override
  public void deleteByTable(String dbName, String tableName) {
    jdbcTemplate.update("DELETE FROM " + this.tableName
        + " WHERE " + DB_NAME_FIELD + " = ? AND " + TABLE_NAME_FIELD + " = ?", dbName, tableName);
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
  public void renameTable(
      String oldDbName, String oldTableName, String newDbName, String newTableName) {
    jdbcTemplate.update("UPDATE " + tableName
            + " SET " + DB_NAME_FIELD + " = ?, " + TABLE_NAME_FIELD + " = ?"
            + " WHERE " + DB_NAME_FIELD + " = ? AND " + TABLE_NAME_FIELD + " = ?",
        newDbName, newTableName, oldDbName, oldTableName);
  }

  @Override
  public void replaceLocation(
      String dbName, String tableName, String oldLocation, String newLocation) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put("dbName", dbName);
    parameters.put("tableName", tableName);
    parameters.put("oldLocation", addPathSeparator(oldLocation));
    parameters.put("newLocation", addPathSeparator(newLocation));

    // all the stored locations end with the path separator, so the prefix check
    // covers both the old location itself and the locations inside it
    namedJdbcTemplate.update("UPDATE " + this.tableName
        + " SET " + LOCATION_FIELD + " = :newLocation"
        + " || SUBSTRING(" + LOCATION_FIELD + " FROM LENGTH(:oldLocation) + 1)"
        + " WHERE " + DB_NAME_FIELD + " = :dbName AND " + TABLE_NAME_FIELD + " = :tableName"
        + " AND STARTS_WITH(" + LOCATION_FIELD + ", :oldLocation)",
        parameters);
  }

  private HivePartitionInfo mapRow(ResultSet resultSet, int rowNum) throws SQLException {
    return HivePartitionInfo.builder()
        .dbName(resultSet.getString(DB_NAME_FIELD))
        .tableName(resultSet.getString(TABLE_NAME_FIELD))
        .name(resultSet.getString(NAME_FIELD))
        .location(resultSet.getString(LOCATION_FIELD))
        .build();
  }

  private Map<String, Object> toMap(HivePartitionInfo partition) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put(DB_NAME_FIELD, partition.getDbName());
    parameters.put(TABLE_NAME_FIELD, partition.getTableName());
    parameters.put(NAME_FIELD, partition.getName());
    parameters.put(LOCATION_FIELD, addPathSeparator(partition.getLocation()));
    return parameters;
  }
}
