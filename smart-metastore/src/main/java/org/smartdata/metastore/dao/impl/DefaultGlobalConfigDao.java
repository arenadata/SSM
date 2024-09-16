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

import org.apache.commons.lang3.StringUtils;
import org.smartdata.metastore.dao.AbstractDao;
import org.smartdata.metastore.dao.GlobalConfigDao;
import org.smartdata.model.GlobalConfig;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DefaultGlobalConfigDao extends AbstractDao implements GlobalConfigDao {
  private static final String TABLE_NAME = "global_config";

  public DefaultGlobalConfigDao(DataSource dataSource) {
    super(dataSource, TABLE_NAME);
  }

  @Override
  public List<GlobalConfig> getAll() {
    return jdbcTemplate.query("SELECT * FROM global_config", new GlobalConfigRowMapper());
  }

  @Override
  public List<GlobalConfig> getByIds(List<Long> cid) {
    return jdbcTemplate.query(
        "SELECT * FROM global_config WHERE cid IN (?)",
        new Object[]{StringUtils.join(cid, ",")},
        new GlobalConfigRowMapper());
  }

  @Override
  public GlobalConfig getById(long cid) {
    return jdbcTemplate.queryForObject(
        "SELECT * FROM global_config WHERE cid = ?",
        new Object[]{cid},
        new GlobalConfigRowMapper());
  }

  @Override
  public GlobalConfig getByPropertyName(String propertyName) {
    return jdbcTemplate.queryForObject(
        "SELECT * FROM global_config WHERE property_name = ?",
        new Object[]{propertyName},
        new GlobalConfigRowMapper());
  }

  @Override
  public void deleteByName(String propertyName) {
    final String sql = "DELETE FROM global_config WHERE property_name = ?";
    jdbcTemplate.update(sql, propertyName);
  }

  @Override
  public void delete(long cid) {
    final String sql = "DELETE FROM global_config WHERE cid = ?";
    jdbcTemplate.update(sql, cid);
  }

  @Override
  public long insert(GlobalConfig globalConfig) {
    SimpleJdbcInsert simpleJdbcInsert = simpleJdbcInsert();
    long cid = simpleJdbcInsert.executeAndReturnKey(toMaps(globalConfig)).longValue();
    globalConfig.setCid(cid);
    return cid;
  }

  // TODO slove the increment of key
  @Override
  public void insert(GlobalConfig[] globalConfigs) {
    SimpleJdbcInsert simpleJdbcInsert = simpleJdbcInsert();
    Map<String, Object>[] maps = new Map[globalConfigs.length];
    for (int i = 0; i < globalConfigs.length; i++) {
      maps[i] = toMaps(globalConfigs[i]);
    }

    int[] cids = simpleJdbcInsert.executeBatch(maps);
    for (int i = 0; i < globalConfigs.length; i++) {
      globalConfigs[i].setCid(cids[i]);
    }
  }

  @Override
  public long getCountByName(String name) {
    return jdbcTemplate.queryForObject(
        "SELECT COUNT(*) FROM global_config WHERE property_name = ?", Long.class, name);
  }

  @Override
  public int update(String propertyName, String propertyValue) {
    String sql = "UPDATE global_config SET property_value = ? WHERE property_name = ?";
    return jdbcTemplate.update(sql, propertyValue, propertyName);
  }

  @Override
  protected SimpleJdbcInsert simpleJdbcInsert() {
    return super.simpleJdbcInsert()
        .usingGeneratedKeyColumns("cid");
  }

  private Map<String, Object> toMaps(GlobalConfig globalConfig) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put("cid", globalConfig.getCid());
    parameters.put("property_name", globalConfig.getPropertyName());
    parameters.put("property_value", globalConfig.getPropertyValue());
    return parameters;
  }

  private static class GlobalConfigRowMapper implements RowMapper<GlobalConfig> {

    @Override
    public GlobalConfig mapRow(ResultSet resultSet, int i) throws SQLException {
      GlobalConfig globalConfig = new GlobalConfig();
      globalConfig.setCid(resultSet.getLong("cid"));
      globalConfig.setPropertyName(resultSet.getString("property_name"));
      globalConfig.setPropertyValue(resultSet.getString("property_value"));
      return globalConfig;
    }
  }
}
