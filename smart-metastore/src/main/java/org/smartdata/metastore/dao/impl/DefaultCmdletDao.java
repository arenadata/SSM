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
import org.smartdata.metastore.SearchableAbstractDao;
import org.smartdata.metastore.dao.CmdletDao;
import org.smartdata.metastore.queries.MetastoreQuery;
import org.smartdata.metastore.queries.sort.CmdletSortField;
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.CmdletState;
import org.smartdata.model.request.CmdletSearchRequest;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static org.smartdata.metastore.queries.MetastoreQuery.selectAll;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.betweenEpochInclusive;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.equal;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.in;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.like;

public class DefaultCmdletDao
    extends SearchableAbstractDao<CmdletSearchRequest, CmdletInfo, CmdletSortField>
    implements CmdletDao {
  private static final String TABLE_NAME = "cmdlet";
  private final String terminatedStates;

  public DefaultCmdletDao(
      DataSource dataSource, PlatformTransactionManager transactionManager) {
    super(dataSource, transactionManager, TABLE_NAME);
    terminatedStates = getTerminatedStatesString();
  }

  @Override
  public CmdletInfo getById(long id) {
    MetastoreQuery query = selectAll()
        .from(TABLE_NAME)
        .where(
            equal("cid", id)
        );
    return executeSingle(query)
        .orElseThrow(() -> new EmptyResultDataAccessException(
            "Cmdlet not found for id" + id, 1));
  }

  @Override
  public List<CmdletInfo> getByRuleId(long ruleId) {
    MetastoreQuery query = selectAll()
        .from(TABLE_NAME)
        .where(
            equal("rid", ruleId)
        );
    return executeQuery(query);
  }

  @Override
  public List<CmdletInfo> getByState(CmdletState state) {
    MetastoreQuery query = selectAll()
        .from(TABLE_NAME)
        .where(
            equal("state", state.getValue())
        );
    return executeQuery(query);
  }

  @Override
  public long getNumCmdletsInTerminiatedStates() {
    MetastoreQuery query = selectAll()
        .from(TABLE_NAME)
        .where(
            in("state", getTerminalStateValues())
        );

    return queryExecutor.executeCount(query);
  }

  @Override
  public boolean delete(long id) {
    final String sql = "DELETE FROM " + TABLE_NAME + " WHERE cid = ?";
    return jdbcTemplate.update(sql, id) != 0;
  }

  @Override
  public void batchDelete(final List<Long> ids) {
    final String sql = "DELETE FROM " + TABLE_NAME + " WHERE cid = ?";
    jdbcTemplate.batchUpdate(
        sql,
        new BatchPreparedStatementSetter() {
          public void setValues(PreparedStatement ps, int i) throws SQLException {
            ps.setLong(1, ids.get(i));
          }

          public int getBatchSize() {
            return ids.size();
          }
        });
  }

  @Override
  public int deleteBeforeTime(long timestamp) {

    final String querysql = "SELECT cid FROM " + TABLE_NAME
        + " WHERE  generate_time < ? AND state IN (" + terminatedStates + ")";
    List<Long> cids = jdbcTemplate.queryForList(querysql, new Object[] {timestamp}, Long.class);
    if (cids.isEmpty()) {
      return 0;
    }
    final String deleteCmds = "DELETE FROM " + TABLE_NAME
        + " WHERE generate_time < ? AND state IN (" + terminatedStates + ")";
    jdbcTemplate.update(deleteCmds, timestamp);
    final String deleteActions = "DELETE FROM action WHERE cid IN ("
        + StringUtils.join(cids, ",") + ")";
    jdbcTemplate.update(deleteActions);
    return cids.size();
  }

  @Override
  public int deleteKeepNewCmd(long num) {
    final String queryCids = "SELECT cid FROM " + TABLE_NAME
        + " WHERE state IN (" + terminatedStates + ")"
        + " ORDER BY generate_time DESC LIMIT 100000 OFFSET " + num;
    List<Long> cids = jdbcTemplate.queryForList(queryCids, Long.class);
    if (cids.isEmpty()) {
      return 0;
    }
    String deleteCids = StringUtils.join(cids, ",");
    final String deleteCmd = "DELETE FROM " + TABLE_NAME + " WHERE cid IN (" + deleteCids + ")";
    jdbcTemplate.update(deleteCmd);
    final String deleteActions = "DELETE FROM action WHERE cid IN (" + deleteCids + ")";
    jdbcTemplate.update(deleteActions);
    return cids.size();
  }

  @Override
  public void insert(CmdletInfo cmdletInfo) {
    insert(cmdletInfo, this::toMap);
  }

  @Override
  public void insert(CmdletInfo... cmdletInfos) {
    insert(cmdletInfos, this::toMap);
  }

  @Override
  public void upsert(final List<CmdletInfo> cmdletInfos) {
    String sql = "REPLACE INTO " + TABLE_NAME
        + "(cid, "
        + "rid, "
        + "aids, "
        + "state, "
        + "parameters, "
        + "generate_time, "
        + "state_changed_time)"
        + " VALUES(?, ?, ?, ?, ?, ?, ?)";

    jdbcTemplate.batchUpdate(
        sql,
        new BatchPreparedStatementSetter() {
          public void setValues(PreparedStatement ps, int i) throws SQLException {
            CmdletInfo cmdletInfo = cmdletInfos.get(i);
            ps.setLong(1, cmdletInfo.getId());
            ps.setLong(2, cmdletInfo.getRuleId());
            ps.setString(3, actionIdsToString(cmdletInfo.getActionIds()));
            ps.setLong(4, cmdletInfo.getState().getValue());
            ps.setString(5, cmdletInfo.getParameters());
            ps.setLong(6, cmdletInfo.getGenerateTime());
            ps.setLong(7, cmdletInfo.getStateChangedTime());
          }

          public int getBatchSize() {
            return cmdletInfos.size();
          }
        });
  }

  @Override
  public int update(final CmdletInfo cmdletInfo) {
    List<CmdletInfo> cmdletInfos = new ArrayList<>();
    cmdletInfos.add(cmdletInfo);
    return update(cmdletInfos)[0];
  }

  @Override
  public int[] update(final List<CmdletInfo> cmdletInfos) {
    String sql = "UPDATE " + TABLE_NAME + " SET  state = ?, state_changed_time = ? WHERE cid = ?";
    return jdbcTemplate.batchUpdate(
        sql,
        new BatchPreparedStatementSetter() {
          public void setValues(PreparedStatement ps, int i) throws SQLException {
            ps.setInt(1, cmdletInfos.get(i).getState().getValue());
            ps.setLong(2, cmdletInfos.get(i).getStateChangedTime());
            ps.setLong(3, cmdletInfos.get(i).getId());
          }

          public int getBatchSize() {
            return cmdletInfos.size();
          }
        });
  }

  @Override
  public long getMaxId() {
    Long ret = jdbcTemplate.queryForObject("SELECT MAX(cid) FROM " + TABLE_NAME, Long.class);
    if (ret == null) {
      return 0;
    } else {
      return ret + 1;
    }
  }

  protected Map<String, Object> toMap(CmdletInfo cmdletInfo) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put("cid", cmdletInfo.getId());
    parameters.put("rid", cmdletInfo.getRuleId());
    parameters.put("aids", actionIdsToString(cmdletInfo.getActionIds()));
    parameters.put("state", cmdletInfo.getState().getValue());
    parameters.put("parameters", cmdletInfo.getParameters());
    parameters.put("generate_time", cmdletInfo.getGenerateTime());
    parameters.put("state_changed_time", cmdletInfo.getStateChangedTime());
    return parameters;
  }

  private String getTerminatedStatesString() {
    return getTerminalStateValues()
        .stream()
        .map(Objects::toString)
        .collect(Collectors.joining(","));
  }

  private List<Integer> getTerminalStateValues() {
    return CmdletState.getTerminalStates()
        .stream()
        .map(CmdletState::getValue)
        .collect(Collectors.toList());
  }

  @Override
  protected MetastoreQuery searchQuery(CmdletSearchRequest searchRequest) {
    List<Integer> stateValues = CollectionUtils.emptyIfNull(searchRequest.getStates())
        .stream()
        .map(CmdletState::getValue)
        .collect(Collectors.toList());

    return selectAll()
        .from(TABLE_NAME)
        .where(
            in("cid", searchRequest.getIds()),
            like("parameters", searchRequest.getTextRepresentationLike()),
            betweenEpochInclusive("generate_time",
                searchRequest.getSubmissionTime()),
            in("rid", searchRequest.getRuleIds()),
            in("state", stateValues),
            betweenEpochInclusive("state_changed_time",
                searchRequest.getStateChangedTime())
        );
  }

  @Override
  protected CmdletInfo mapRow(ResultSet resultSet, int rowNum) throws SQLException {
    return CmdletInfo.builder()
        .setId(resultSet.getLong("cid"))
        .setRuleId(resultSet.getLong("rid"))
        .setActionIds(parseRawIds(resultSet.getString("aids")))
        .setState(CmdletState.fromValue(resultSet.getByte("state")))
        .setParameters(resultSet.getString("parameters"))
        .setGenerateTime(resultSet.getLong("generate_time"))
        .setStateChangedTime(resultSet.getLong("state_changed_time"))
        .build();
  }

  private List<Long> parseRawIds(String rawIds) {
    return StringUtils.isBlank(rawIds)
        ? Collections.emptyList()
        : Arrays.stream(rawIds.split(","))
        .map(Long::valueOf)
        .collect(Collectors.toList());
  }

  private String actionIdsToString(List<Long> ids) {
    return CollectionUtils.emptyIfNull(ids)
        .stream()
        .map(Object::toString)
        .collect(Collectors.joining(","));
  }
}
