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

import org.smartdata.metastore.dao.AbstractDao;
import org.smartdata.metastore.dao.StorageDao;
import org.smartdata.model.StorageCapacity;
import org.smartdata.model.StoragePolicy;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;

import javax.sql.DataSource;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DefaultStorageDao extends AbstractDao implements StorageDao {
  private static final String TABLE_NAME = "storage";

  public DefaultStorageDao(DataSource dataSource) {
    super(dataSource, TABLE_NAME);
  }

  @Override
  public Map<String, StorageCapacity> getStorageTablesItem() {
    String sql = "SELECT * FROM storage";
    List<StorageCapacity> list = jdbcTemplate.query(sql,
        new StorageCapacityRowMapper());
    Map<String, StorageCapacity> map = new HashMap<>();
    for (StorageCapacity s : list) {
      map.put(s.getType(), s);
    }
    return map;
  }

  @Override
  public Map<Integer, String> getStoragePolicyIdNameMap() {
    String sql = "SELECT * FROM storage_policy";
    List<StoragePolicy> list = jdbcTemplate.query(sql,
        (rs, rowNum) -> new StoragePolicy(
            rs.getByte("sid"),
            rs.getString("policy_name")));
    Map<Integer, String> map = new HashMap<>();
    for (StoragePolicy s : list) {
      map.put((int) (s.getSid()), s.getPolicyName());
    }
    return map;
  }

  @Override
  public StorageCapacity getStorageCapacity(String type) {
    String sql = "SELECT * FROM storage WHERE type = ?";
    return jdbcTemplate.queryForObject(sql, new Object[] {type},
        new StorageCapacityRowMapper());
  }

  @Override
  public void updateFileStoragePolicy(String path,
                                      Integer policyId) {
    String sql = String.format(
        "UPDATE file SET sid = %d WHERE path = '%s';",
        policyId, path);
    jdbcTemplate.update(sql);
  }

  @Override
  public void insertUpdateStoragesTable(List<StorageCapacity> storages)
      throws SQLException {
    if (storages.isEmpty()) {
      return;
    }
    final Long curr = System.currentTimeMillis();
    String sql = "REPLACE INTO storage (type, time_stamp, capacity, free) VALUES (?,?,?,?);";
    jdbcTemplate.batchUpdate(sql,
        new BatchPreparedStatementSetter() {
          public void setValues(PreparedStatement ps,
                                int i) throws SQLException {
            StorageCapacity capacity = storages.get(i);
            ps.setString(1, capacity.getType());
            if (capacity.getTimeStamp() == null) {
              ps.setLong(2, curr);
            } else {
              ps.setLong(2, capacity.getTimeStamp());
            }
            ps.setLong(3, capacity.getCapacity());
            ps.setLong(4, capacity.getFree());
          }

          public int getBatchSize() {
            return storages.size();
          }
        });
  }

  @Override
  public void deleteStorage(String storageType) {
    final String sql = "DELETE FROM storage WHERE type = ?";
    jdbcTemplate.update(sql, storageType);
  }

  private static class StorageCapacityRowMapper implements RowMapper<StorageCapacity> {
    @Override
    public StorageCapacity mapRow(ResultSet resultSet, int i)
        throws SQLException {
      return new StorageCapacity(
          resultSet.getString("type"),
          resultSet.getLong("time_stamp"),
          resultSet.getLong("capacity"),
          resultSet.getLong("free"));
    }
  }
}
