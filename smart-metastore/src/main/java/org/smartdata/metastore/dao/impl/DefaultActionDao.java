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

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.lang.StringEscapeUtils;
import org.smartdata.metastore.SearchableAbstractDao;
import org.smartdata.metastore.dao.ActionDao;
import org.smartdata.metastore.queries.MetastoreQuery;
import org.smartdata.metastore.queries.expression.MetastoreQueryExpression;
import org.smartdata.metastore.queries.sort.ActionSortField;
import org.smartdata.metastore.queries.sort.Sorting;
import org.smartdata.model.ActionInfo;
import org.smartdata.model.ActionSource;
import org.smartdata.model.ActionState;
import org.smartdata.model.CmdletDescriptor;
import org.smartdata.model.request.ActionSearchRequest;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;

import java.lang.reflect.Type;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.smartdata.metastore.queries.MetastoreQuery.selectAll;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.and;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.betweenEpochInclusive;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.equal;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.in;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.like;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.notLike;
import static org.smartdata.metastore.queries.sort.Sorting.descending;

public class DefaultActionDao
    extends SearchableAbstractDao<ActionSearchRequest, ActionInfo, ActionSortField>
    implements ActionDao {

  private static final String TABLE_NAME = "action";
  private static final Type ACTION_ARGS_TYPE =
      new TypeToken<Map<String, String>>() {
      }.getType();

  private final Gson argsJsonSerializer;

  public DefaultActionDao(
      DataSource dataSource,
      PlatformTransactionManager transactionManager) {
    super(dataSource, transactionManager, TABLE_NAME);
    this.argsJsonSerializer = new Gson();
  }

  @Override
  public ActionInfo getById(long aid) {
    MetastoreQuery query = selectAll()
        .from(TABLE_NAME)
        .where(
            equal("aid", aid)
        );

    return executeSingle(query)
        .orElseThrow(() -> new EmptyResultDataAccessException(1));
  }

  @Override
  public List<ActionInfo> getByIds(List<Long> aids) {
    return executeQuery(
        selectAll()
            .from(TABLE_NAME)
            .where(
                in("aid", aids)
            )
    );
  }

  @Override
  public List<ActionInfo> getLatestActions(int size) {
    MetastoreQuery query = selectAll()
        .from(TABLE_NAME)
        .orderBy(descending(ActionSortField.ID));

    if (size != 0) {
      query.limit(size);
    }

    return executeQuery(query);
  }

  @Override
  public void delete(long aid) {
    final String sql = "DELETE FROM " + TABLE_NAME + " WHERE aid = ?";
    jdbcTemplate.update(sql, aid);
  }

  @Override
  public void deleteCmdletActions(long cid) {
    final String sql = "DELETE FROM " + TABLE_NAME + " WHERE cid = ?";
    jdbcTemplate.update(sql, cid);
  }

  @Override
  public int[] batchDeleteCmdletActions(final List<Long> cids) {
    final String sql = "DELETE FROM " + TABLE_NAME + " WHERE cid = ?";
    return jdbcTemplate.batchUpdate(
        sql,
        new BatchPreparedStatementSetter() {
          public void setValues(PreparedStatement ps, int i) throws SQLException {
            ps.setLong(1, cids.get(i));
          }

          public int getBatchSize() {
            return cids.size();
          }
        });
  }

  @Override
  public void insert(ActionInfo actionInfo) {
    insert(actionInfo, this::toMap);
  }

  @Override
  public void insert(ActionInfo... actionInfos) {
    insert(actionInfos, this::toMap);
  }

  @Override
  public void upsert(List<ActionInfo> actionInfos) {
    String sql =
        "REPLACE INTO "
            + TABLE_NAME
            + "(aid, "
            + "cid, "
            + "action_name, "
            + "args, "
            + "result, "
            + "log, "
            + "successful, "
            + "create_time, "
            + "finished, "
            + "finish_time, "
            + "exec_host, "
            + "progress, "
            + "action_text, "
            + "source) "
            + " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    jdbcTemplate.batchUpdate(sql,
        new BatchPreparedStatementSetter() {
          public void setValues(PreparedStatement ps,
                                int i) throws SQLException {
            ActionInfo actionInfo = actionInfos.get(i);
            ps.setLong(1, actionInfo.getActionId());
            ps.setLong(2, actionInfo.getCmdletId());
            ps.setString(3, actionInfo.getActionName());
            ps.setString(4, serializeArgs(actionInfo.getArgs()));
            ps.setString(5, actionInfo.getResult());
            ps.setString(6, actionInfo.getLog());
            ps.setBoolean(7, actionInfo.isSuccessful());
            ps.setLong(8, actionInfo.getCreateTime());
            ps.setBoolean(9, actionInfo.isFinished());
            ps.setLong(10, actionInfo.getFinishTime());
            ps.setString(11, actionInfo.getExecHost());
            ps.setFloat(12, actionInfo.getProgress());
            ps.setString(13, actionInfo.getActionText());
            ps.setString(14, actionInfo.getSource().toString());
          }

          public int getBatchSize() {
            return actionInfos.size();
          }
        });
  }

  @Override
  public int update(final ActionInfo actionInfo) {
    return update(new ActionInfo[] {actionInfo})[0];
  }

  @Override
  public int[] update(final ActionInfo[] actionInfos) {
    String sql =
        "UPDATE "
            + TABLE_NAME
            + " SET "
            + "result = ?, "
            + "log = ?, "
            + "successful = ?, "
            + "create_time = ?, "
            + "finished = ?, "
            + "finish_time = ?, "
            + "exec_host = ?, "
            + "progress = ?, "
            + "action_text = ?, "
            + "source = ? "
            + "WHERE aid = ?";
    return jdbcTemplate.batchUpdate(sql,
        new BatchPreparedStatementSetter() {
          public void setValues(PreparedStatement ps,
                                int i) throws SQLException {
            ActionInfo actionInfo = actionInfos[i];
            ps.setString(1, actionInfo.getResult());
            ps.setString(2, actionInfo.getLog());
            ps.setBoolean(3, actionInfo.isSuccessful());
            ps.setLong(4, actionInfo.getCreateTime());
            ps.setBoolean(5, actionInfo.isFinished());
            ps.setLong(6, actionInfo.getFinishTime());
            ps.setString(7, actionInfo.getExecHost());
            ps.setFloat(8, actionInfo.getProgress());
            ps.setString(9, actionInfo.getActionText());
            ps.setString(10, actionInfo.getSource().toString());
            ps.setLong(11, actionInfo.getActionId());
          }

          public int getBatchSize() {
            return actionInfos.length;
          }
        });
  }

  @Override
  public long getMaxId() {
    Long ret = jdbcTemplate
        .queryForObject("SELECT MAX(aid) FROM " + TABLE_NAME, Long.class);
    if (ret == null) {
      return 0;
    } else {
      return ret + 1;
    }
  }

  protected Map<String, Object> toMap(ActionInfo actionInfo) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put("aid", actionInfo.getActionId());
    parameters.put("cid", actionInfo.getCmdletId());
    parameters.put("action_name", actionInfo.getActionName());
    parameters.put("args", serializeArgs(actionInfo.getArgs()));
    parameters
        .put("result", StringEscapeUtils.escapeJava(actionInfo.getResult()));
    parameters.put("log", StringEscapeUtils.escapeJava(actionInfo.getLog()));
    parameters.put("successful", actionInfo.isSuccessful());
    parameters.put("create_time", actionInfo.getCreateTime());
    parameters.put("finished", actionInfo.isFinished());
    parameters.put("finish_time", actionInfo.getFinishTime());
    parameters.put("exec_host", actionInfo.getExecHost());
    parameters.put("progress", actionInfo.getProgress());
    parameters.put("action_text", actionInfo.getActionText());
    parameters.put("source", actionInfo.getSource().toString());
    return parameters;
  }

  @Override
  protected MetastoreQuery searchQuery(ActionSearchRequest searchRequest) {
    return selectAll()
        .from(TABLE_NAME)
        .where(
            in("aid", searchRequest.getIds()),
            like("action_text", searchRequest.getTextRepresentationLike()),
            betweenEpochInclusive("create_time", searchRequest.getSubmissionTime()),
            in("exec_host", searchRequest.getHosts()),
            betweenEpochInclusive("finish_time", searchRequest.getCompletionTime()),
            buildQueryOperator(searchRequest.getSources(), this::sourceToExpression),
            buildQueryOperator(searchRequest.getStates(), this::stateToExpression)
        );
  }

  @Override
  protected Stream<Sorting<String>> toDbColumnSortings(
      ActionSortField column, Sorting.Order order) {
    if (column != ActionSortField.STATUS) {
      return super.toDbColumnSortings(column, order);
    }

    return Stream.of(
        new Sorting<>("finished", order),
        new Sorting<>("successful", order)
    );
  }

  private MetastoreQueryExpression sourceToExpression(ActionSource source) {
    return source == ActionSource.RULE
        ? like("args", CmdletDescriptor.RULE_ID)
        : notLike("args", CmdletDescriptor.RULE_ID);
  }

  private MetastoreQueryExpression stateToExpression(ActionState state) {
    switch (state) {
      case FAILED:
        return and(
            equal("finished", true),
            equal("successful", false)
        );
      case SUCCESSFUL:
        return and(
            equal("finished", true),
            equal("successful", true)
        );
      default:
        return equal("finished", false);
    }
  }

  private Map<String, String> deserializeArgs(String json) {
    return argsJsonSerializer.fromJson(json, ACTION_ARGS_TYPE);
  }

  private String serializeArgs(Map<String, String> args) {
    return argsJsonSerializer.toJson(args);
  }

  @Override
  protected ActionInfo mapRow(ResultSet resultSet, int rowNum) throws SQLException {
    return sharedActionBuilder(resultSet)
        .setArgs(deserializeArgs(resultSet.getString("args")))
        .setResult(
            StringEscapeUtils.unescapeJava(resultSet.getString("result")))
        .setLog(StringEscapeUtils.unescapeJava(resultSet.getString("log")))
        .build();
  }

  private ActionInfo.Builder sharedActionBuilder(ResultSet resultSet) throws SQLException {
    return ActionInfo.builder()
        .setActionId(resultSet.getLong("aid"))
        .setCmdletId(resultSet.getLong("cid"))
        .setActionName(resultSet.getString("action_name"))
        .setSuccessful(resultSet.getBoolean("successful"))
        .setCreateTime(resultSet.getLong("create_time"))
        .setFinished(resultSet.getBoolean("finished"))
        .setFinishTime(resultSet.getLong("finish_time"))
        .setExecHost(resultSet.getString("exec_host"))
        .setProgress(resultSet.getFloat("progress"));
  }
}
