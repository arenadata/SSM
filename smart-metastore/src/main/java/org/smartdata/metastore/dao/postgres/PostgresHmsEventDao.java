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

import org.smartdata.hive.HmsEventDao;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.metastore.dao.AbstractDao;
import org.smartdata.metastore.queries.MetastoreQuery;
import org.smartdata.metastore.queries.MetastoreQueryExecutor;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.TransactionCallback;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.smartdata.hive.fetch.HiveNotificationEvent.extractRelatedResources;
import static org.smartdata.metastore.queries.MetastoreQuery.selectAll;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.equal;

public class PostgresHmsEventDao extends AbstractDao implements HmsEventDao {
  private static final String EVENTS_TABLE_NAME = "hive_metastore_event";
  private static final String IGNORED_EVENTS_TABLE_NAME = "ignored_hive_metastore_event";

  private static final String ID_FIELD = "id";
  private static final String EXTERNAL_ID_FIELD = "external_id";
  private static final String EVENT_TIME_FIELD = "event_time";
  private static final String EVENT_TYPE_FIELD = "event_type";
  private static final String ENTITY_NAME_FIELD = "entity_name";
  private static final String ENTITY_TYPE_FIELD = "entity_type";
  private static final String CATALOG_NAME_FIELD = "catalog_name";
  private static final String DB_NAME_FIELD = "db_name";
  private static final String TABLE_NAME_FIELD = "table_name";
  private static final String MESSAGE_FIELD = "message";
  private static final String MESSAGE_FORMAT_FIELD = "message_format";
  private static final String RELATED_RESOURCES_FIELD = "related_resources";

  private final MetastoreQueryExecutor queryExecutor;
  private final PostgresInsertSupport insertSupport;

  public PostgresHmsEventDao(DataSource dataSource,
      PlatformTransactionManager transactionManager,
      String tableName) {
    super(dataSource, tableName);

    this.insertSupport = new PostgresInsertSupport(dataSource, tableName);
    this.queryExecutor = new MetastoreQueryExecutor(dataSource, transactionManager);
  }

  @Override
  protected SimpleJdbcInsert simpleJdbcInsert() {
    return super.simpleJdbcInsert()
        .usingGeneratedKeyColumns(ID_FIELD);
  }

  @Override
  public void insert(HiveNotificationEvent event) {
    insert(event, this::toMap);
  }

  @Override
  public void insertIfNotPresent(HiveNotificationEvent event) {
    insertSupport.insertIfNotPresent(toMap(event), MESSAGE_FIELD);
  }

  @Override
  public HiveNotificationEvent get(long eventId) {
    MetastoreQuery query = selectAll()
        .from(tableName)
        .where(
            equal("id", eventId)
        );

    return queryExecutor.executeSingle(query, this::mapRow)
        .orElseThrow(() -> new EmptyResultDataAccessException(
            "HMS event with following id not found: " + eventId, 1));
  }

  @Override
  public void deleteAll() {
    jdbcTemplate.update("DELETE FROM " + tableName);
  }

  @Override
  public void deleteEventsFor(String fullName) {
    jdbcTemplate.update(
        "DELETE FROM " + tableName + " WHERE entity_name = ?", fullName);
  }

  @Override
  public Optional<Long> getLatestExternalEventId() {
    Long result = jdbcTemplate.queryForObject(
        "SELECT MAX(external_id) FROM " + tableName,
        Long.class
    );

    return Optional.ofNullable(result);
  }

  private HiveNotificationEvent mapRow(ResultSet resultSet, int rowNum) throws SQLException {
    return HiveNotificationEvent.builder()
        .id(resultSet.getLong(ID_FIELD))
        .externalId(resultSet.getLong(EXTERNAL_ID_FIELD))
        .eventTime(resultSet.getLong(EVENT_TIME_FIELD))
        .eventType(resultSet.getString(EVENT_TYPE_FIELD))
        .entityType(resultSet.getString(ENTITY_TYPE_FIELD))
        .fullName(resultSet.getString(ENTITY_NAME_FIELD))
        .catalogName(resultSet.getString(CATALOG_NAME_FIELD))
        .dbName(resultSet.getString(DB_NAME_FIELD))
        .tableName(resultSet.getString(TABLE_NAME_FIELD))
        .message(resultSet.getString(MESSAGE_FIELD))
        .messageFormat(resultSet.getString(MESSAGE_FORMAT_FIELD))
        .relatedResources(extractRelatedResources(
            resultSet.getString(RELATED_RESOURCES_FIELD)))
        .build();
  }

  private Map<String, Object> toMap(HiveNotificationEvent event) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put(EXTERNAL_ID_FIELD, event.getExternalId());
    parameters.put(EVENT_TIME_FIELD, event.getEventTime());
    parameters.put(EVENT_TYPE_FIELD, event.getEventType());
    parameters.put(ENTITY_TYPE_FIELD, event.getEntityType());
    parameters.put(ENTITY_NAME_FIELD, event.getFullName());
    parameters.put(CATALOG_NAME_FIELD, event.getCatalogName());
    parameters.put(DB_NAME_FIELD, event.getDbName());
    parameters.put(TABLE_NAME_FIELD, event.getTableName());
    parameters.put(MESSAGE_FIELD, event.getMessage());
    parameters.put(MESSAGE_FORMAT_FIELD, event.getMessageFormat());
    parameters.put(RELATED_RESOURCES_FIELD, event.rawRelatedResources());
    return parameters;
  }

  public static PostgresHmsEventDao baseEventsDao(
      DataSource dataSource, PlatformTransactionManager transactionManager) {
    return new PostgresHmsEventDao(dataSource, transactionManager, EVENTS_TABLE_NAME);
  }

  public static PostgresHmsEventDao ignoredEventsDao(
      DataSource dataSource, PlatformTransactionManager transactionManager) {
    return new PostgresHmsEventDao(dataSource, transactionManager, IGNORED_EVENTS_TABLE_NAME);
  }

  @Override
  public <T> T execute(TransactionCallback<T> action) throws TransactionException {
    return queryExecutor.execute(action);
  }
}
