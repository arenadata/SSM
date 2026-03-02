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
package org.smartdata.test.suite.hms;

import io.arenadata.test.model.UserRole;
import io.arenadata.test.service.ContainerManager;
import io.qameta.allure.Feature;
import io.qameta.allure.Story;
import io.qameta.allure.TmsLink;
import org.smartdata.test.dao.impl.HiveMetastoreEventDaoImpl;
import org.smartdata.test.dao.impl.HiveSyncProgressDaoImpl;
import org.smartdata.test.service.SqlExecutor;
import org.smartdata.test.step.DataBaseStep;
import org.smartdata.test.step.LoginStep;
import org.smartdata.test.step.MenuStep;
import org.smartdata.test.step.PaginationStep;
import org.smartdata.test.step.RulesStep;
import org.smartdata.test.step.TableStep;
import org.smartdata.test.suite.SsmWebBaseSuite;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Ignore;
import org.testng.annotations.Test;

import javax.sql.DataSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.ACTION;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.STATUS;
import static org.smartdata.test.element.PaginationElement.PageSize.THIRTY;
import static org.smartdata.test.model.ActionStatus.SUCCESSFUL;
import static org.smartdata.test.model.SsmComponent.SSM_SERVER;

@Feature("HMS replication")
public class HmsWebTestSuite extends SsmWebBaseSuite {
  @Autowired
  private ContainerManager containerManager;
  @Autowired
  private LoginStep loginStep;
  @Autowired
  private MenuStep menuStep;
  @Autowired
  private RulesStep rulesStep;
  @Autowired
  private TableStep tableStep;
  @Autowired
  private PaginationStep paginationStep;
  @Autowired
  private DataBaseStep dataBaseStep;
  @Autowired
  private HiveMetastoreEventDaoImpl hiveMetastoreEventDao;
  @Autowired
  private HiveSyncProgressDaoImpl hiveSyncProgressDao;
  @Autowired
  private SqlExecutor sqlExecutor;
  @Autowired
  @Qualifier("hiveServer2DataSource")
  private DataSource hiveServer2DataSource;
  @Autowired
  @Qualifier("targetHiveServer2DataSource")
  private DataSource targetHiveServer2DataSource;

  private static final String TEST_DATABASE_1 = "db1";
  private static final String TEST_DATABASE_2 = "db2";
  private static final String HMS_SYNC_RULE_TEMPLATE =
      "hms : name matches \"%s.*\" | hms-sync -dest thrift://target-hive-metastore:9083/ -cascade -nameservice_rename \"source target\"";

  @BeforeMethod
  public void restoreEnv() {
    containerManager.stop(SSM_SERVER);
    dataBaseStep.dropHiveServersTable(TEST_DATABASE_1)
        .dropHiveServersTable(TEST_DATABASE_2)
        .truncateSsmHiveNotificationLogTable();
    hiveMetastoreEventDao.deleteAll();
    hiveSyncProgressDao.deleteAll();
    containerManager.start(SSM_SERVER);
    loginStep.loginAs(UserRole.OWNER);
    menuStep.openRulesPage();
  }

  @TmsLink("136492")
  @Story("HMS Configuration")
  @Test(description = "Check HMS rule and actions")
  public void testHmsRuleAndActions() {
    rulesStep.createRule(format(HMS_SYNC_RULE_TEMPLATE, TEST_DATABASE_2))
        .startRuleInFirstRow();
    dataBaseStep.prepareDataForHmsRulesAndActionsTest();
    menuStep.openActionsPage();
    paginationStep.setShowPerPageOption(THIRTY, null);
    checkSuccessSyncActions(19, TEST_DATABASE_2);
  }

  @TmsLink("136575")
  @Story("HMS Configuration")
  @Test(description = "Check HMS rule for constraints")
  public void testHmsRuleForConstraints() {
    rulesStep.createRule(format(HMS_SYNC_RULE_TEMPLATE, TEST_DATABASE_1))
        .startRuleInFirstRow();
    dataBaseStep.createHiveServerDatabase(TEST_DATABASE_1);
    sqlExecutor.executeSql(hiveServer2DataSource,
        "CREATE TABLE db1.students (id INT, name  STRING NOT NULL, email STRING DEFAULT 'unknown');");
    menuStep.openActionsPage();
    tableStep.setRefreshingFrequency(1);
    checkSuccessSyncActions(4, TEST_DATABASE_1);
    checkConstraintsEquals(TEST_DATABASE_1, "students", 2);
    sqlExecutor.executeSql(hiveServer2DataSource,
        "ALTER TABLE db1.students ADD CONSTRAINT students_pk PRIMARY KEY (id) DISABLE NOVALIDATE;\n" +
            "CREATE TABLE db1.students_data (data_id INT, student_id INT);\n" +
            "ALTER TABLE db1.students_data ADD CONSTRAINT students_data_fk FOREIGN KEY (student_id) REFERENCES db1.students(id) DISABLE NOVALIDATE;");
    checkSuccessSyncActions(7, TEST_DATABASE_1);
    checkConstraintsEquals(TEST_DATABASE_1, "students", 3);
    checkConstraintsEquals(TEST_DATABASE_1, "students_data", 1);
    sqlExecutor.executeSql(hiveServer2DataSource,
        "ALTER TABLE db1.students_data DROP CONSTRAINT students_data_fk;\n" +
            "ALTER TABLE db1.students DROP CONSTRAINT students_pk;");
    checkSuccessSyncActions(9, TEST_DATABASE_1);
    checkConstraintsEquals(TEST_DATABASE_1, "students", 2);
    checkConstraintsEquals(TEST_DATABASE_1, "students_data", 0);
  }

  @TmsLink("136571")
  @Story("HMS Configuration")
  @Test(description = "Check HMS rule for databases")
  public void testHmsRuleForDatabases() {
    rulesStep.createRule(format(HMS_SYNC_RULE_TEMPLATE, TEST_DATABASE_1))
        .startRuleInFirstRow();
    dataBaseStep.createHiveServerDatabase(TEST_DATABASE_1);
    menuStep.openActionsPage();
    tableStep.setRefreshingFrequency(1);
    checkSuccessSyncActions(1, TEST_DATABASE_1);
    checkDatabaseParameters(hiveServer2DataSource, TEST_DATABASE_1, "");
    checkDatabaseParameters(targetHiveServer2DataSource, TEST_DATABASE_1, "");
    sqlExecutor.executeSql(hiveServer2DataSource, "ALTER DATABASE db1 SET dbproperties ('Date' = '2026-01-13');");
    checkSuccessSyncActions(2, TEST_DATABASE_1);
    checkDatabaseParameters(hiveServer2DataSource, TEST_DATABASE_1, "{Date=2026-01-13}");
    checkDatabaseParameters(targetHiveServer2DataSource, TEST_DATABASE_1, "{Date=2026-01-13}");
    sqlExecutor.executeSql(hiveServer2DataSource, "DROP DATABASE db1;");
    checkSuccessSyncActions(3, TEST_DATABASE_1);
    checkDatabaseIsNotExist(hiveServer2DataSource, TEST_DATABASE_1);
    checkDatabaseIsNotExist(targetHiveServer2DataSource, TEST_DATABASE_1);
  }

  @TmsLink("136574")
  @Story("HMS Configuration")
  @Test(description = "Check HMS rule for functions")
  @Ignore("functions sync not work")
  public void testHmsRuleForFunctions() {
    rulesStep.createRule(format(HMS_SYNC_RULE_TEMPLATE, TEST_DATABASE_1))
        .startRuleInFirstRow();
    dataBaseStep.createHiveServerDatabase(TEST_DATABASE_1);
    menuStep.openActionsPage();
    tableStep.setRefreshingFrequency(1);
    checkSuccessSyncActions(1, TEST_DATABASE_1);
    sqlExecutor.executeSql(hiveServer2DataSource,
        "CREATE FUNCTION db1.sum_cols AS 'org.apache.hadoop.hive.ql.udf.generic.GenericUDFOPPlus';");
    checkSuccessSyncActions(2, TEST_DATABASE_1);
    sqlExecutor.executeSql(targetHiveServer2DataSource, "reload functions;");
    checkFunctionResult(hiveServer2DataSource, "select db1.sum_cols(1,3)", 4);
    checkFunctionResult(targetHiveServer2DataSource, "select db1.sum_cols(1,3)", 4);
    sqlExecutor.executeSql(hiveServer2DataSource, "DROP FUNCTION db1.sum_cols;");
    checkSuccessSyncActions(3, TEST_DATABASE_1);
    sqlExecutor.executeSql(targetHiveServer2DataSource, "reload functions;");
    checkFunctionNotExists(hiveServer2DataSource, "sum_cols");
    checkFunctionNotExists(targetHiveServer2DataSource, "sum_cols");
  }

  @TmsLink("136573")
  @Story("HMS Configuration")
  @Test(description = "Check HMS rule for partitions")
  public void testHmsRuleForPartitions() {
    rulesStep.createRule(format(HMS_SYNC_RULE_TEMPLATE, TEST_DATABASE_1))
        .startRuleInFirstRow();
    dataBaseStep.createHiveServerDatabase(TEST_DATABASE_1);
    sqlExecutor.executeSql(hiveServer2DataSource,
        "CREATE TABLE db1.clients (id   INT, name STRING )     PARTITIONED BY (month STRING);");
    sqlExecutor.executeSql(hiveServer2DataSource,
        "alter table db1.clients add partition (month='december');");
    menuStep.openActionsPage();
    tableStep.setRefreshingFrequency(1);
    checkSuccessSyncActions(3, TEST_DATABASE_1);
    assertThat(getPartitions(hiveServer2DataSource, "db1.clients")).singleElement().isEqualTo("month=december");
    assertThat(getPartitions(targetHiveServer2DataSource, "db1.clients")).singleElement().isEqualTo("month=december");
    sqlExecutor.executeSql(hiveServer2DataSource,
        "alter table db1.clients partition (month='december') rename to partition (month='january');");
    checkSuccessSyncActions(4, TEST_DATABASE_1);
    assertThat(getPartitions(hiveServer2DataSource, "db1.clients")).singleElement().isEqualTo("month=january");
    assertThat(getPartitions(targetHiveServer2DataSource, "db1.clients")).singleElement().isEqualTo("month=january");
    sqlExecutor.executeSql(hiveServer2DataSource,
        "alter table db1.clients drop partition (month='january');");
    checkSuccessSyncActions(5, TEST_DATABASE_1);
    assertThat(getPartitions(hiveServer2DataSource, "db1.clients")).isEmpty();
    assertThat(getPartitions(targetHiveServer2DataSource, "db1.clients")).isEmpty();
  }

  @TmsLink("136572")
  @Story("HMS Configuration")
  @Test(description = "Check HMS rule for tables")
  public void testHmsRuleForTables() {
    Map<String, Object> colI = new HashMap<>();
    colI.put("col_name", "i");
    colI.put("data_type", "int");
    colI.put("comment", "");
    Map<String, Object> colJ = new HashMap<>();
    colJ.put("col_name", "j");
    colJ.put("data_type", "string");
    colJ.put("comment", "");
    rulesStep.createRule(format(HMS_SYNC_RULE_TEMPLATE, TEST_DATABASE_1))
        .startRuleInFirstRow();
    dataBaseStep.createHiveServerDatabase(TEST_DATABASE_1);
    sqlExecutor.executeSql(hiveServer2DataSource, "create table db1.t1 (i INT)");
    menuStep.openActionsPage();
    tableStep.setRefreshingFrequency(1);
    checkSuccessSyncActions(2, TEST_DATABASE_1);
    checkTableColumnsWithParams(hiveServer2DataSource, "db1.t1", Collections.singletonList(colI));
    checkTableColumnsWithParams(targetHiveServer2DataSource, "db1.t1", Collections.singletonList(colI));
    sqlExecutor.executeSql(hiveServer2DataSource, "alter table db1.t1 add columns (j string);");
    checkSuccessSyncActions(3, TEST_DATABASE_1);
    checkTableColumnsWithParams(hiveServer2DataSource, "db1.t1", Arrays.asList(colJ, colI));
    checkTableColumnsWithParams(targetHiveServer2DataSource, "db1.t1", Arrays.asList(colJ, colI));
    sqlExecutor.executeSql(hiveServer2DataSource, "drop table db1.t1");
    checkSuccessSyncActions(4, TEST_DATABASE_1);
    checkTableIsNotExist(hiveServer2DataSource, "db1", "t1");
    checkTableIsNotExist(targetHiveServer2DataSource, "db1", "t1");
  }

  public List<Map<String, Object>> getTableConstraints(DataSource dataSource, String database, String table) {
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    String sql = String.format("DESCRIBE EXTENDED %s.%s", database, table);
    List<Map<String, Object>> result = jdbcTemplate.queryForList(sql);
    return result.stream()
        .filter(row -> row.get("col_name") != null
            && row.get("col_name").toString().toLowerCase().contains("constraint"))
        .collect(Collectors.toList());
  }

  private void checkConstraintsEquals(String database, String table, int expectedSize) {
    List<Map<String, Object>> sourceConstraints = getTableConstraints(hiveServer2DataSource, database, table);
    List<Map<String, Object>> targetConstraints = getTableConstraints(targetHiveServer2DataSource, database, table);
    assertThat(targetConstraints).hasSize(expectedSize).containsExactlyInAnyOrderElementsOf(sourceConstraints);
  }

  private void checkSuccessSyncActions(int expectedSize, String entityName) {
    tableStep.checkTableRowsCountIs(expectedSize)
        .checkAllColumnCellsContain(expectedSize, ACTION, format("-entityName %s", entityName))
        .checkAllColumnCellsTextEqual(expectedSize, STATUS, SUCCESSFUL.getText());
  }

  private void checkDatabaseParameters(DataSource dataSource, String database, String expectedParameters) {
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    String sql = String.format("DESCRIBE DATABASE EXTENDED %s", database);
    List<Map<String, Object>> result = jdbcTemplate.queryForList(sql);
    String parameters = result.stream()
        .map(row -> row.get("parameters"))
        .filter(Objects::nonNull)
        .map(Object::toString)
        .findFirst()
        .orElse(null);
    assertThat(parameters).isEqualTo(expectedParameters);
  }

  // move general methods to database step
  private void checkDatabaseIsNotExist(DataSource dataSource, String database) {
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    List<Map<String, Object>> result = jdbcTemplate.queryForList("SHOW DATABASES");
    List<String> databases = result.stream()
        .map(row -> row.values().iterator().next())
        .filter(Objects::nonNull)
        .map(Object::toString)
        .collect(Collectors.toList());
    assertThat(databases).isNotEmpty().doesNotContain(database);
  }

  private void checkTableIsNotExist(DataSource dataSource, String database, String table) {
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    List<Map<String, Object>> result = jdbcTemplate.queryForList(format("show tables in %s", database));
    List<String> databases = result.stream()
        .map(row -> row.values().iterator().next())
        .filter(Objects::nonNull)
        .map(Object::toString)
        .collect(Collectors.toList());
    assertThat(databases).doesNotContain(table);
  }

  private void checkFunctionNotExists(DataSource dataSource, String functionName) {
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    List<Map<String, Object>> result = jdbcTemplate.queryForList("SHOW FUNCTIONS");
    List<String> functions = result.stream()
        .map(row -> row.values().iterator().next())
        .filter(Objects::nonNull)
        .map(Object::toString)
        .collect(Collectors.toList());
    assertThat(functions).doesNotContain(functionName);
  }

  private void checkFunctionResult(DataSource dataSource, String sql, int expectedResult) {
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    List<Map<String, Object>> result = jdbcTemplate.queryForList(sql);
    Integer actual = result.stream()
        .map(row -> row.values().iterator().next())
        .filter(Objects::nonNull)
        .map(v -> Integer.parseInt(v.toString()))
        .findFirst()
        .orElse(null);
    assertThat(actual).isEqualTo(expectedResult);
  }

  private List<String> getPartitions(DataSource dataSource, String table) {
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    List<Map<String, Object>> result = jdbcTemplate.queryForList(format("show partitions %s", table));
    return result.stream()
        .map(row -> row.values().iterator().next())
        .filter(Objects::nonNull)
        .map(Object::toString)
        .collect(Collectors.toList());
  }

  private void checkTableColumnsWithParams(DataSource dataSource, String table, List<Map<String, Object>> expectedColumns) {
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    List<Map<String, Object>> result = jdbcTemplate.queryForList(format("DESCRIBE %s", table));
    List<Map<String, Object>> actualColumns = result.stream()
        .filter(row -> row.get("col_name") != null && !row.get("col_name").toString().trim().isEmpty())
        .collect(Collectors.toList());
    assertThat(actualColumns).containsExactlyInAnyOrderElementsOf(expectedColumns);
  }
}
