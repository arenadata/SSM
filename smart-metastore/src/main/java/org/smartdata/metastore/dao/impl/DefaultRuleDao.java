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
import org.smartdata.metastore.SearchableAbstractDao;
import org.smartdata.metastore.dao.RuleDao;
import org.smartdata.metastore.queries.MetastoreQuery;
import org.smartdata.metastore.queries.sort.RuleSortField;
import org.smartdata.model.RuleInfo;
import org.smartdata.model.RuleState;
import org.smartdata.model.RulesInfo;
import org.smartdata.model.request.RuleSearchRequest;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.smartdata.metastore.queries.MetastoreQuery.select;
import static org.smartdata.metastore.queries.MetastoreQuery.selectAll;
import static org.smartdata.metastore.queries.column.MetastoreQueryColumnDsl.countAll;
import static org.smartdata.metastore.queries.column.MetastoreQueryColumnDsl.countFiltered;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.betweenEpochInclusive;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.equal;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.in;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.likeCaseInsensitive;

public class DefaultRuleDao
    extends SearchableAbstractDao<RuleSearchRequest, RuleInfo, RuleSortField>
    implements RuleDao {
  private static final String TABLE_NAME = "rule";

  private static final String TOTAL_RULES_COUNT_COLUMN = "total_rules_count";
  private static final String ACTIVE_RULES_COUNT_COLUMN = "active_rules_count";

  private static final List<RuleState> SEARCHABLE_STATES = Arrays.asList(
      RuleState.ACTIVE, RuleState.NEW, RuleState.DISABLED, RuleState.FINISHED);

  public DefaultRuleDao(
      DataSource dataSource, PlatformTransactionManager transactionManager) {
    super(dataSource, transactionManager, TABLE_NAME);
  }

  @Override
  public List<RuleInfo> getAll() {
    MetastoreQuery query = selectAll().from(TABLE_NAME);
    return executeQuery(query);
  }

  @Override
  public RuleInfo getById(long id) {
    MetastoreQuery query = selectAll()
        .from(TABLE_NAME)
        .where(
            equal("id", id)
        );

    return executeSingle(query)
        .orElseThrow(() -> new EmptyResultDataAccessException(
            "Rule with following id not found: " + id, 1));
  }

  @Override
  public RulesInfo getRulesInfo() {
    MetastoreQuery query = select(
        countAll(TOTAL_RULES_COUNT_COLUMN),
        countFiltered(ACTIVE_RULES_COUNT_COLUMN,
            equal("state", RuleState.ACTIVE.getValue()))
    ).from(TABLE_NAME);

    return executeSingle(query, this::mapRulesInfoRow)
        .orElse(new RulesInfo(0L, 0L));
  }

  @Override
  public long insert(RuleInfo ruleInfo) {
    SimpleJdbcInsert simpleJdbcInsert = simpleJdbcInsert();
    simpleJdbcInsert.usingGeneratedKeyColumns("id");
    long id = simpleJdbcInsert.executeAndReturnKey(toMap(ruleInfo)).longValue();
    ruleInfo.setId(id);
    return id;
  }

  @Override
  public int update(long ruleId, long lastCheckTime, long checkedCount, int cmdletsGen) {
    String sql =
        "UPDATE rule SET last_check_time = ?, checked_count = ?, "
            + "generated_cmdlets = ? WHERE id = ?";
    return jdbcTemplate.update(sql, lastCheckTime, checkedCount, cmdletsGen, ruleId);
  }

  @Override
  public int update(long ruleId, int rs, long lastCheckTime, long checkedCount, int cmdletsGen) {
    String sql =
        "UPDATE rule SET state = ?, last_check_time = ?, checked_count = ?, "
            + "generated_cmdlets = ? WHERE id = ?";
    return jdbcTemplate.update(sql, rs, lastCheckTime, checkedCount, cmdletsGen, ruleId);
  }

  @Override
  public int update(long ruleId, int rs) {
    String sql = "UPDATE rule SET state = ? WHERE id = ?";
    return jdbcTemplate.update(sql, rs, ruleId);
  }

  @Override
  public void delete(long id) {
    final String sql = "DELETE FROM rule WHERE id = ?";
    jdbcTemplate.update(sql, id);
  }

  private Map<String, Object> toMap(RuleInfo ruleInfo) {
    Map<String, Object> parameters = new HashMap<>();
    if (ruleInfo.getSubmitTime() == 0) {
      ruleInfo.setSubmitTime(System.currentTimeMillis());
    }
    parameters.put("submit_time", ruleInfo.getSubmitTime());
    parameters.put("rule_text", ruleInfo.getRuleText());
    parameters.put("state", ruleInfo.getState().getValue());
    parameters.put("checked_count", ruleInfo.getNumChecked());
    parameters.put("generated_cmdlets", ruleInfo.getNumCmdsGen());
    parameters.put("last_check_time", ruleInfo.getLastCheckTime());
    parameters.put("owner", ruleInfo.getOwner());
    return parameters;
  }

  @Override
  protected MetastoreQuery searchQuery(RuleSearchRequest searchRequest) {
    List<Integer> stateValues = Optional.ofNullable(searchRequest.getStates())
        .filter(CollectionUtils::isNotEmpty)
        .orElseGet(() -> getDefaultStates(searchRequest))
        .stream()
        .map(RuleState::getValue)
        .collect(Collectors.toList());

    return selectAll()
        .from(TABLE_NAME)
        .where(
            in("id", searchRequest.getIds()),
            likeCaseInsensitive("rule_text", searchRequest.getTextRepresentationLike()),
            betweenEpochInclusive("submit_time", searchRequest.getSubmissionTime()),
            in("state", stateValues),
            betweenEpochInclusive("last_check_time",
                searchRequest.getLastActivationTime())
        );
  }

  @Override
  protected RuleInfo mapRow(ResultSet resultSet, int rowNum) throws SQLException {
    return RuleInfo.builder()
        .setId(resultSet.getLong("id"))
        .setSubmitTime(resultSet.getLong("submit_time"))
        .setRuleText(resultSet.getString("rule_text"))
        .setState(RuleState.fromValue(resultSet.getByte("state")))
        .setNumChecked(resultSet.getLong("checked_count"))
        .setNumCmdsGen(resultSet.getLong("generated_cmdlets"))
        .setLastCheckTime(resultSet.getObject("last_check_time", Long.class))
        .setOwner(resultSet.getString("owner"))
        .build();
  }

  private List<RuleState> getDefaultStates(RuleSearchRequest searchRequest) {
    return searchRequest.isIncludeDeletedRules()
        ? Collections.emptyList()
        : SEARCHABLE_STATES;
  }

  private RulesInfo mapRulesInfoRow(ResultSet resultSet, int row) throws SQLException {
    return new RulesInfo(
        resultSet.getLong(TOTAL_RULES_COUNT_COLUMN),
        resultSet.getLong(ACTIVE_RULES_COUNT_COLUMN));
  }
}
