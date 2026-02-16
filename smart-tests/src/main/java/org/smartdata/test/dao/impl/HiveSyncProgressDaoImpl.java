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
import org.smartdata.test.dao.HiveSyncProgressDao;
import org.smartdata.test.entity.HiveSyncProgressEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Implementation of HiveSyncProgressDao using Spring JDBC Template.
 */
@Slf4j
@Repository
public class HiveSyncProgressDaoImpl implements HiveSyncProgressDao {
  private static final String TABLE_NAME = "hive_sync_progress";
  private static final String SELECT_ALL = "SELECT rule_id, event_id FROM " + TABLE_NAME;
  private static final String DELETE_ALL = "DELETE FROM " + TABLE_NAME;
  private final JdbcTemplate jdbcTemplate;

  @Autowired
  public HiveSyncProgressDaoImpl(@Qualifier("ssmMetastoreJdbcTemplate") JdbcTemplate jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
  }

  @Override
  public List<HiveSyncProgressEntity> findAll() {
    return jdbcTemplate.query(
        SELECT_ALL,
        BeanPropertyRowMapper.newInstance(HiveSyncProgressEntity.class)
    );
  }

  @Override
  public int deleteAll() {
    return jdbcTemplate.update(DELETE_ALL);
  }
}
