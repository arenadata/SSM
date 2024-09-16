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
import org.smartdata.metastore.dao.FileDiffDao;
import org.smartdata.model.FileDiff;
import org.smartdata.model.FileDiffState;
import org.smartdata.model.FileDiffType;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;

import javax.sql.DataSource;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class DefaultFileDiffDao extends AbstractDao implements FileDiffDao {
  private static final String TABLE_NAME = "file_diff";
  public String uselessFileDiffStates;

  public DefaultFileDiffDao(DataSource dataSource) {
    super(dataSource, TABLE_NAME);
    this.uselessFileDiffStates = getUselessFileDiffState();
  }

  @Override
  public String getUselessFileDiffState() {
    List<String> stateValues = new ArrayList<>();
    for (FileDiffState state : FileDiffState.getUselessFileDiffState()) {
      stateValues.add(String.valueOf(state.getValue()));
    }
    return StringUtils.join(stateValues, ",");
  }

  @Override
  public List<FileDiff> getAll() {
    return jdbcTemplate.query("SELECT * FROM " + TABLE_NAME, new FileDiffRowMapper());
  }

  @Override
  public List<FileDiff> getPendingDiff() {
    return jdbcTemplate.query(
        "SELECT * FROM " + TABLE_NAME + " WHERE state = 0", new FileDiffRowMapper());
  }

  @Override
  public List<FileDiff> getByState(String prefix, FileDiffState fileDiffState) {
    return jdbcTemplate
        .query(
            "SELECT * FROM " + TABLE_NAME + " WHERE src LIKE ? and state = ?",
            new Object[]{prefix + "%", fileDiffState.getValue()},
            new FileDiffRowMapper());
  }

  @Override
  public List<FileDiff> getPendingDiff(long rid) {
    return jdbcTemplate.query("SELECT * FROM " + TABLE_NAME + " WHERE did = ? and state = 0",
        new Object[]{rid},
        new FileDiffRowMapper());
  }

  @Override
  public List<FileDiff> getPendingDiff(String prefix) {
    return jdbcTemplate.query("SELECT * FROM " + TABLE_NAME + " WHERE src LIKE ? and state = 0",
        new FileDiffRowMapper(), prefix + "%");
  }

  @Override
  public List<FileDiff> getByIds(List<Long> dids) {
    return jdbcTemplate.query("SELECT * FROM " + TABLE_NAME + " WHERE did IN (?)",
        new Object[]{StringUtils.join(dids, ",")},
        new FileDiffRowMapper());
  }

  @Override
  public List<FileDiff> getByFileName(String fileName) {
    return jdbcTemplate.query("SELECT * FROM " + TABLE_NAME + " WHERE src = ?",
        new Object[]{fileName}, new FileDiffRowMapper());
  }

  @Override
  public List<String> getSyncPath(int size) {
    if (size != 0) {
      jdbcTemplate.setMaxRows(size);
    }
    String sql = "SELECT DISTINCT src FROM " + TABLE_NAME + " WHERE state = ?";
    return jdbcTemplate
        .queryForList(sql, String.class, FileDiffState.RUNNING.getValue());
  }

  @Override
  public FileDiff getById(long did) {
    return jdbcTemplate.queryForObject("SELECT * FROM " + TABLE_NAME + " WHERE did = ?",
        new Object[]{did}, new FileDiffRowMapper());
  }

  @Override
  public void delete(long did) {
    final String sql = "DELETE FROM " + TABLE_NAME + " WHERE did = ?";
    jdbcTemplate.update(sql, did);
  }

  @Override
  public int getUselessRecordsNum() {
    final String query = "SELECT count(*) FROM " + TABLE_NAME + " WHERE state IN ("
        + uselessFileDiffStates + ")";
    return jdbcTemplate.queryForObject(query, Integer.class);
  }

  @Override
  public int deleteUselessRecords(int num) {
    final String queryDids = "SELECT did FROM " + TABLE_NAME + " WHERE state IN ("
        + uselessFileDiffStates + ") ORDER BY create_time DESC LIMIT 1000 OFFSET " + num;
    List<Long> dids = jdbcTemplate.queryForList(queryDids, Long.class);
    if (dids.isEmpty()) {
      return 0;
    }
    String unusedDids = StringUtils.join(dids, ",");
    final String deleteUnusedFileDiff = "DELETE FROM " + TABLE_NAME + " where did IN ("
        + unusedDids + ")";
    jdbcTemplate.update(deleteUnusedFileDiff);
    return dids.size();
  }

  @Override
  public long insert(FileDiff fileDiff) {
    SimpleJdbcInsert simpleJdbcInsert = simpleJdbcInsert();
    simpleJdbcInsert.usingGeneratedKeyColumns("did");
    // return did
    long did = simpleJdbcInsert.executeAndReturnKey(toMap(fileDiff)).longValue();
    fileDiff.setDiffId(did);
    return did;
  }

  @Override
  public void insert(FileDiff[] fileDiffs) {
    insert(fileDiffs, this::toMap);
  }

  @Override
  public List<Long> insert(List<FileDiff> fileDiffs) {
    return fileDiffs.stream()
        .map(this::insert)
        .collect(Collectors.toList());
  }

  @Override
  public int[] batchUpdate(
      final List<Long> dids, final List<FileDiffState> states,
      final List<String> parameters) {

    final String sql = "UPDATE " + TABLE_NAME + " SET state = ?, "
        + "parameters = ? WHERE did = ?";
    return jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
      @Override
      public void setValues(PreparedStatement ps, int i) throws SQLException {
        ps.setShort(1, (short) states.get(i).getValue());
        ps.setString(2, parameters.get(i));
        ps.setLong(3, dids.get(i));
      }

      @Override
      public int getBatchSize() {
        return dids.size();
      }
    });
  }

  @Override
  public int[] batchUpdate(
      final List<Long> dids, final FileDiffState state) {

    final String sql = "UPDATE " + TABLE_NAME + " SET state = ? "
        + "WHERE did = ?";
    return jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
      @Override
      public void setValues(PreparedStatement ps, int i) throws SQLException {
        ps.setShort(1, (short) state.getValue());
        ps.setLong(2, dids.get(i));
      }

      @Override
      public int getBatchSize() {
        return dids.size();
      }
    });
  }


  @Override
  public int update(long did, FileDiffState state) {
    String sql = "UPDATE " + TABLE_NAME + " SET state = ? WHERE did = ?";
    return jdbcTemplate.update(sql, state.getValue(), did);
  }

  @Override
  public int update(long did, String src) {
    String sql = "UPDATE " + TABLE_NAME + " SET src = ? WHERE did = ?";
    return jdbcTemplate.update(sql, src, did);
  }

  @Override
  public int update(long did, FileDiffState state,
                    String parameters) {
    String sql = "UPDATE " + TABLE_NAME + " SET state = ?, "
        + "parameters = ? WHERE did = ?";
    return jdbcTemplate.update(sql, state.getValue(), parameters, did);
  }

  @Override
  public void update(final List<FileDiff> fileDiffs) {
    String sql = "UPDATE " + TABLE_NAME + " SET "
        + "rid = ?, "
        + "diff_type = ?, "
        + "src = ?, "
        + "parameters = ?, "
        + "state = ?, "
        + "create_time = ? "
        + "WHERE did = ?";
    jdbcTemplate.batchUpdate(sql,
        new BatchPreparedStatementSetter() {
          @Override
          public void setValues(PreparedStatement ps,
                                int i) throws SQLException {
            FileDiff fileDiff = fileDiffs.get(i);
            ps.setLong(1, fileDiff.getRuleId());
            ps.setInt(2, fileDiff.getDiffType().getValue());
            ps.setString(3, fileDiff.getSrc());
            ps.setString(4, fileDiff.getParametersJsonString());
            ps.setInt(5, fileDiff.getState().getValue());
            ps.setLong(6, fileDiff.getCreateTime());
            ps.setLong(7, fileDiff.getDiffId());
          }

          @Override
          public int getBatchSize() {
            return fileDiffs.size();
          }
        });
  }

  @Override
  public int update(final FileDiff fileDiff) {
    String sql = "UPDATE " + TABLE_NAME + " SET "
        + "rid = ?, "
        + "diff_type = ?, "
        + "src = ?, "
        + "parameters = ?, "
        + "state = ?, "
        + "create_time = ? "
        + "WHERE did = ?";
    return jdbcTemplate.update(sql, fileDiff.getRuleId(),
        fileDiff.getDiffType().getValue(), fileDiff.getSrc(),
        fileDiff.getParametersJsonString(), fileDiff.getState().getValue(),
        fileDiff.getCreateTime(), fileDiff.getDiffId());
  }


  @Override
  public void deleteAll() {
    final String sql = "DELETE FROM " + TABLE_NAME;
    jdbcTemplate.execute(sql);
  }

  private Map<String, Object> toMap(FileDiff fileDiff) {
    // System.out.println(fileDiff.getDiffType());
    Map<String, Object> parameters = new HashMap<>();
    parameters.put("did", fileDiff.getDiffId());
    parameters.put("rid", fileDiff.getRuleId());
    parameters.put("diff_type", fileDiff.getDiffType().getValue());
    parameters.put("src", fileDiff.getSrc());
    parameters.put("parameters", fileDiff.getParametersJsonString());
    parameters.put("state", fileDiff.getState().getValue());
    parameters.put("create_time", fileDiff.getCreateTime());
    return parameters;
  }

  private static class FileDiffRowMapper implements RowMapper<FileDiff> {
    @Override
    public FileDiff mapRow(ResultSet resultSet, int i) throws SQLException {
      FileDiff fileDiff = new FileDiff();
      fileDiff.setDiffId(resultSet.getLong("did"));
      fileDiff.setRuleId(resultSet.getLong("rid"));
      fileDiff.setDiffType(FileDiffType.fromValue((int) resultSet.getByte("diff_type")));
      fileDiff.setSrc(resultSet.getString("src"));
      fileDiff.setParametersFromJsonString(resultSet.getString("parameters"));
      fileDiff.setState(FileDiffState.fromValue((int) resultSet.getByte("state")));
      fileDiff.setCreateTime(resultSet.getLong("create_time"));
      return fileDiff;
    }
  }
}
