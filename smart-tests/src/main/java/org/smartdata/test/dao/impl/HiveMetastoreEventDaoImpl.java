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
package org.smartdata.test.dao.impl;

import lombok.extern.slf4j.Slf4j;
import org.smartdata.test.dao.HiveMetastoreEventDao;
import org.smartdata.test.entity.HiveMetastoreEventEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

/**
 * Implementation of HiveMetastoreEventDao using Spring JDBC Template.
 */
@Slf4j
@Repository
public class HiveMetastoreEventDaoImpl implements HiveMetastoreEventDao {
  private static final String TABLE_NAME = "hive_metastore_event";
  private static final String SELECT_ALL =
      "SELECT id, external_id, event_time, event_type, entity_name, entity_type, " +
          "catalog_name, db_name, table_name, message, message_format " +
          "FROM " + TABLE_NAME;
  private final JdbcTemplate jdbcTemplate;

  @Autowired
  public HiveMetastoreEventDaoImpl(@Qualifier("ssmMetastoreJdbcTemplate") JdbcTemplate jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
  }

  @Override
  public List<HiveMetastoreEventEntity> findAll() {
    return jdbcTemplate.query(SELECT_ALL, new HiveMetastoreEventRowMapper());
  }

  /**
   * RowMapper to convert ResultSet rows to HiveMetastoreEventEntity objects.
   */
  private static class HiveMetastoreEventRowMapper implements RowMapper<HiveMetastoreEventEntity> {
    @Override
    public HiveMetastoreEventEntity mapRow(ResultSet rs, int rowNum) throws SQLException {
      HiveMetastoreEventEntity entity = new HiveMetastoreEventEntity();
      entity.setId(rs.getLong("id"));
      entity.setExternalId(rs.getLong("external_id"));
      entity.setEventTime(rs.getLong("event_time"));
      entity.setEventType(rs.getString("event_type"));
      entity.setEntityName(rs.getString("entity_name"));
      entity.setEntityType(rs.getString("entity_type"));
      entity.setCatalogName(rs.getString("catalog_name"));
      entity.setDbName(rs.getString("db_name"));
      entity.setTableName(rs.getString("table_name"));
      entity.setMessage(rs.getString("message"));
      entity.setMessageFormat(rs.getString("message_format"));
      return entity;
    }
  }
}
