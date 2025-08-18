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
package org.smartdata.test.step;


import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.smartdata.test.repository.MetastoreRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Instant;

import static java.time.temporal.ChronoUnit.HOURS;

@Slf4j
@Service
public class DataBaseStep {

  @Autowired
  private MetastoreRepository metastoreRepository;

  private static final String TRUNCATE_RULE_TABLE = "TRUNCATE TABLE rule;";
  private static final String RESET_RULE_SEQUENCE = "ALTER SEQUENCE rule_id_seq RESTART WITH 1;";
  private static final String RULES_FOR_SORT_TEST_SQL = "src/test/resources/data/sql/insert_rules_for_sort_test.sql";
  private static final String ACTIONS_FOR_SORT_TEST_SQL = "src/test/resources/data/sql/insert_actions_for_sort_test.sql";
  private static final String ACTION_FOR_FILTER_TEST_SQL = "src/test/resources/data/sql/insert_action_for_filter_test.sql";
  private static final String RULES_FILTER_TEMPLATE = "INSERT INTO rule" +
      "(\"name\", state, rule_text, submit_time, last_check_time, checked_count, generated_cmdlets, \"owner\") " +
      "VALUES(NULL, ?, ?, ?, ?, 1, 1, 'john');";
  private static final String TRUNCATE_ACTION_TABLE = "TRUNCATE TABLE action;";

  public DataBaseStep cleanRuleTable() throws SQLException {
    metastoreRepository.executeSql(TRUNCATE_RULE_TABLE);
    metastoreRepository.executeSql(RESET_RULE_SEQUENCE);
    return this;
  }

  public DataBaseStep cleanActionTable() throws SQLException {
    metastoreRepository.executeSql(TRUNCATE_ACTION_TABLE);
    return this;
  }

  @SneakyThrows
  public DataBaseStep insertDataForRulesSortTest() {
    metastoreRepository.executeSqlFile(RULES_FOR_SORT_TEST_SQL);
    return this;
  }

  @SneakyThrows
  public DataBaseStep insertDataForRulesFilterTest() {
    String firstRule = "file: every 1s | path matches \"/*\" | sleep -ms 100";
    String secondRule = "file: every 1s | path matches \"/*\" | read";
    try (PreparedStatement ps = metastoreRepository.getConnection().prepareStatement(RULES_FILTER_TEMPLATE)) {
      ps.setInt(1, 0);
      ps.setString(2, firstRule);
      ps.setLong(3, Instant.now().toEpochMilli());
      ps.setLong(4, Instant.now().toEpochMilli());
      ps.execute();
      ps.setInt(1, 1);
      ps.setString(2, secondRule);
      ps.setLong(3, Instant.now().minus(2, HOURS).toEpochMilli());
      ps.setLong(4, Instant.now().minus(2, HOURS).toEpochMilli());
      ps.execute();
    }
    return this;
  }

  @SneakyThrows
  public DataBaseStep insertDataForActionSortTest() {
    metastoreRepository.executeSqlFile(ACTIONS_FOR_SORT_TEST_SQL);
    return this;
  }

  @SneakyThrows
  public DataBaseStep insertDataForActionFilterTest() {
    metastoreRepository.executeSqlFile(ACTION_FOR_FILTER_TEST_SQL);
    return this;
  }
}
