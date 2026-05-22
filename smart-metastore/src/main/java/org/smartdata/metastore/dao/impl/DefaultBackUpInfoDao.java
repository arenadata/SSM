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

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.smartdata.metastore.dao.AbstractDao;
import org.smartdata.metastore.dao.BackUpInfoDao;
import org.smartdata.model.BackUpInfo;
import org.smartdata.model.FileDiffType;
import org.springframework.jdbc.core.RowMapper;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class DefaultBackUpInfoDao extends AbstractDao implements BackUpInfoDao {
  private static final String TABLE_NAME = "backup_file";

  public DefaultBackUpInfoDao(DataSource dataSource) {
    super(dataSource, TABLE_NAME);
  }

  @Override
  public List<BackUpInfo> getAll() {
    return jdbcTemplate.query("SELECT * FROM backup_file", new BackUpInfoRowMapper());
  }

  @Override
  public int getCountByRid(int rid) {
    return jdbcTemplate.queryForObject(
        "SELECT COUNT(*) FROM backup_file WHERE rid = ?", new Object[rid], Integer.class);
  }

  @Override
  public BackUpInfo getByRid(long rid) {
    return jdbcTemplate.queryForObject("SELECT * FROM backup_file WHERE rid = ?",
        new Object[]{rid}, new BackUpInfoRowMapper());
  }

  @Override
  public List<BackUpInfo> getBySrc(String src) {
    return jdbcTemplate.query(
        "SELECT * FROM backup_file WHERE src = ?", new Object[]{src},
        new BackUpInfoRowMapper());
  }

  @Override
  public List<BackUpInfo> getByDest(String dest) {
    return jdbcTemplate.query(
        "SELECT * FROM backup_file WHERE dest = ?", new Object[]{dest},
        new BackUpInfoRowMapper());
  }

  @Override
  public void delete(long rid) {
    final String sql = "DELETE FROM backup_file WHERE rid = ?";
    jdbcTemplate.update(sql, rid);
  }

  @Override
  public void insert(BackUpInfo backUpInfo) {
    insert(backUpInfo, this::toMap);
  }

  @Override
  public void insert(BackUpInfo[] backUpInfos) {
    insert(backUpInfos, this::toMap);
  }

  @Override
  public int update(long rid, long period) {
    String sql = "UPDATE backup_file SET period = ? WHERE rid = ?";
    return jdbcTemplate.update(sql, period, rid);
  }

  @Override
  public void deleteAll() {
    final String sql = "DELETE FROM backup_file";
    jdbcTemplate.execute(sql);
  }

  private Map<String, Object> toMap(BackUpInfo backUpInfo) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put("rid", backUpInfo.getRid());
    parameters.put("src", backUpInfo.getSrc());
    parameters.put("dest", backUpInfo.getDest());
    parameters.put("period", backUpInfo.getPeriod());
    parameters.put("src_pattern", backUpInfo.getSrcPattern());
    parameters.put("included_diff_types", serializeDiffTypes(backUpInfo.getIncludedFileDiffTypes()));
    return parameters;
  }

  private static String serializeDiffTypes(Set<FileDiffType> diffTypes) {
    return CollectionUtils.emptyIfNull(diffTypes)
        .stream()
        .map(FileDiffType::name)
        .collect(Collectors.joining(","));
  }

  private static Set<FileDiffType> parseDiffTypes(String raw) {
    return StringUtils.isBlank(raw)
        ? Collections.emptySet()
        : Arrays.stream(raw.split(","))
          .map(FileDiffType::valueOf)
          .collect(Collectors.toSet());
  }

  private static class BackUpInfoRowMapper implements RowMapper<BackUpInfo> {

    @Override
    public BackUpInfo mapRow(ResultSet resultSet, int i) throws SQLException {
      return BackUpInfo.builder()
          .rid(resultSet.getLong("rid"))
          .src(resultSet.getString("src"))
          .dest(resultSet.getString("dest"))
          .period(resultSet.getLong("period"))
          .srcPattern(resultSet.getString("src_pattern"))
          .includedFileDiffTypes(parseDiffTypes(resultSet.getString("included_diff_types")))
          .build();
    }
  }
}
