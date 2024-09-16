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
import org.smartdata.metastore.dao.ClusterConfigDao;
import org.smartdata.model.ClusterConfig;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DefaultClusterConfigDao extends AbstractDao implements ClusterConfigDao {
  private static final String TABLE_NAME = "cluster_config";

  public DefaultClusterConfigDao(DataSource dataSource) {
    super(dataSource, TABLE_NAME);
  }

  @Override
  public List<ClusterConfig> getAll() {
    return jdbcTemplate.query("SELECT * FROM cluster_config", new ClusterConfigRowMapper());
  }

  @Override
  public List<ClusterConfig> getByIds(List<Long> cids) {
    return jdbcTemplate.query("SELECT * FROM cluster_config WHERE cid IN (?)",
        new Object[]{StringUtils.join(cids, ",")},
        new ClusterConfigRowMapper());
  }

  @Override
  public ClusterConfig getById(long cid) {
    return jdbcTemplate.queryForObject("SELECT * FROM cluster_config WHERE cid = ?",
        new Object[]{cid}, new ClusterConfigRowMapper());
  }

  @Override
  public long getCountByName(String name) {
    return jdbcTemplate.queryForObject(
        "SELECT COUNT(*) FROM cluster_config WHERE node_name = ?", Long.class, name);
  }

  @Override
  public ClusterConfig getByName(String name) {
    return jdbcTemplate.queryForObject("SELECT * FROM cluster_config WHERE node_name = ?",
        new Object[]{name}, new ClusterConfigRowMapper());
  }

  @Override
  public void delete(long cid) {
    final String sql = "DELETE FROM cluster_config WHERE cid = ?";
    jdbcTemplate.update(sql, cid);
  }

  @Override
  public long insert(ClusterConfig clusterConfig) {
    SimpleJdbcInsert simpleJdbcInsert = simpleJdbcInsert();
    long cid = simpleJdbcInsert.executeAndReturnKey(toMap(clusterConfig)).longValue();
    clusterConfig.setCid(cid);
    return cid;
  }

  // TODO slove the increment of key
  @Override
  public void insert(ClusterConfig[] clusterConfigs) {
    SimpleJdbcInsert simpleJdbcInsert = simpleJdbcInsert();
    Map<String, Object>[] maps = new Map[clusterConfigs.length];
    for (int i = 0; i < clusterConfigs.length; i++) {
      maps[i] = toMap(clusterConfigs[i]);
    }
    int[] cids = simpleJdbcInsert.executeBatch(maps);

    for (int i = 0; i < clusterConfigs.length; i++) {
      clusterConfigs[i].setCid(cids[i]);
    }
  }

  @Override
  public int updateById(int cid, String configPath) {
    final String sql = "UPDATE cluster_config SET config_path = ? WHERE cid = ?";
    return jdbcTemplate.update(sql, configPath, cid);
  }

  @Override
  public int updateByNodeName(String nodeName, String configPath) {
    final String sql = "UPDATE cluster_config SET config_path = ? WHERE node_name = ?";
    return jdbcTemplate.update(sql, configPath, nodeName);
  }

  @Override
  protected SimpleJdbcInsert simpleJdbcInsert() {
    return super.simpleJdbcInsert()
        .usingGeneratedKeyColumns("cid");
  }

  private Map<String, Object> toMap(ClusterConfig clusterConfig) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put("cid", clusterConfig.getCid());
    parameters.put("config_path", clusterConfig.getConfigPath());
    parameters.put("node_name", clusterConfig.getNodeName());
    return parameters;
  }

  private static class ClusterConfigRowMapper implements RowMapper<ClusterConfig> {

    @Override
    public ClusterConfig mapRow(ResultSet resultSet, int i) throws SQLException {
      ClusterConfig clusterConfig = new ClusterConfig();
      clusterConfig.setCid(resultSet.getLong("cid"));
      clusterConfig.setConfig_path(resultSet.getString("config_path"));
      clusterConfig.setNodeName(resultSet.getString("node_name"));

      return clusterConfig;
    }
  }

}
