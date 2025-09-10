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
package org.smartdata.metastore.dao.impl;

import org.smartdata.hive.HmsEventDao;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.metastore.dao.AbstractDao;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;

import javax.sql.DataSource;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class DefaultHmsEventDao extends AbstractDao implements HmsEventDao {
  private static final String EVENTS_TABLE_NAME = "hive_metastore_event";
  private static final String IGNORED_EVENTS_TABLE_NAME = "ignored_hive_metastore_event";

  private static final String ID_FIELD = "id";
  private static final String EXTERNAL_ID_FIELD = "external_id";
  private static final String EVENT_TIME_FIELD = "event_time";
  private static final String EVENT_TYPE_FIELD = "event_type";
  private static final String ENTITY_TYPE_FIELD = "entity_type";
  private static final String CATALOG_NAME_FIELD = "catalog_name";
  private static final String DB_NAME_FIELD = "db_name";
  private static final String TABLE_NAME_FIELD = "table_name";
  private static final String MESSAGE_FIELD = "message";
  private static final String MESSAGE_FORMAT_FIELD = "message_format";

  public DefaultHmsEventDao(DataSource dataSource, String tableName) {
    super(dataSource, tableName);
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
  public void deleteAll() {
    jdbcTemplate.update("DELETE FROM " + tableName);
  }

  @Override
  public Optional<Long> getLatestExternalEventId() {
    Long result = jdbcTemplate.queryForObject(
        "SELECT MAX(external_id) FROM " + tableName,
        Long.class
    );

    return Optional.ofNullable(result);
  }

  private Map<String, Object> toMap(HiveNotificationEvent event) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put(EXTERNAL_ID_FIELD, event.getExternalId());
    parameters.put(EVENT_TIME_FIELD, event.getEventTime());
    parameters.put(EVENT_TYPE_FIELD, event.getEventType());
    parameters.put(ENTITY_TYPE_FIELD, event.getEntityType());
    parameters.put(CATALOG_NAME_FIELD, event.getCatalogName());
    parameters.put(DB_NAME_FIELD, event.getDbName());
    parameters.put(TABLE_NAME_FIELD, event.getTableName());
    parameters.put(MESSAGE_FIELD, event.getMessage());
    parameters.put(MESSAGE_FORMAT_FIELD, event.getMessageFormat());
    return parameters;
  }

  public static DefaultHmsEventDao defaultEventsDao(DataSource dataSource) {
    return new DefaultHmsEventDao(dataSource, EVENTS_TABLE_NAME);
  }

  public static DefaultHmsEventDao ignoredEventsDao(DataSource dataSource) {
    return new DefaultHmsEventDao(dataSource, IGNORED_EVENTS_TABLE_NAME);
  }
}
