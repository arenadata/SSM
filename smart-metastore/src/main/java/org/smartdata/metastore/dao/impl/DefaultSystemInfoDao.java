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
import org.smartdata.metastore.dao.SystemInfoDao;
import org.smartdata.model.SystemInfo;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DefaultSystemInfoDao extends AbstractDao implements SystemInfoDao {
  private static final String TABLE_NAME = "sys_info";

  public DefaultSystemInfoDao(DataSource dataSource) {
    super(dataSource, TABLE_NAME);
  }

  @Override
  public List<SystemInfo> getAll() {
    return jdbcTemplate.query("SELECT * FROM " + TABLE_NAME, new SystemInfoRowMapper());
  }

  @Override
  public boolean containsProperty(String property) {
    return !list(property).isEmpty();
  }

  private List<SystemInfo> list(String property) {
    return new JdbcTemplate(dataSource)
        .query(
            "SELECT * FROM " + TABLE_NAME + " WHERE property = ?",
            new Object[]{property},
            new SystemInfoRowMapper());
  }

  @Override
  public SystemInfo getByProperty(String property) {
    List<SystemInfo> infos = list(property);
    return infos.isEmpty() ? null : infos.get(0);
  }

  @Override
  public List<SystemInfo> getByProperties(List<String> properties) {
    return jdbcTemplate.query("SELECT * FROM " + TABLE_NAME + " WHERE property IN (?)",
        new Object[]{StringUtils.join(properties, ",")},
        new SystemInfoRowMapper());
  }

  @Override
  public void delete(String property) {
    final String sql = "DELETE FROM " + TABLE_NAME + " WHERE property = ?";
    jdbcTemplate.update(sql, property);
  }

  @Override
  public void insert(SystemInfo systemInfo) {
    insert(systemInfo, this::toMap);
  }

  @Override
  public void insert(SystemInfo[] systemInfos) {
    insert(systemInfos, this::toMap);
  }

  @Override
  public int update(SystemInfo systemInfo) {
    String sql = "UPDATE " + TABLE_NAME + " SET value = ? WHERE property = ?";
    return jdbcTemplate.update(sql, systemInfo.getValue(), systemInfo.getProperty());
  }

  @Override
  public void deleteAll() {
    final String sql = "DELETE FROM " + TABLE_NAME;
    jdbcTemplate.execute(sql);
  }

  private Map<String, Object> toMap(SystemInfo systemInfo) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put("property", systemInfo.getProperty());
    parameters.put("value", systemInfo.getValue());
    return parameters;
  }

  private static class SystemInfoRowMapper implements RowMapper<SystemInfo> {

    @Override
    public SystemInfo mapRow(ResultSet resultSet, int i) throws SQLException {
      return new SystemInfo(
          resultSet.getString("property"),
          resultSet.getString("value"));
    }
  }
}
