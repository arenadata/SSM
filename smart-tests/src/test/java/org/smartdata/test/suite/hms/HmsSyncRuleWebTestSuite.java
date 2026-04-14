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
import io.qameta.allure.Step;
import io.qameta.allure.Story;
import io.qameta.allure.TmsLink;
import org.smartdata.test.annotation.RequiredComponents;
import org.smartdata.test.service.SqlExecutor;
import org.smartdata.test.step.ActionsDetailsStep;
import org.smartdata.test.step.ActionsStep;
import org.smartdata.test.step.ApiStep;
import org.smartdata.test.step.DataBaseStep;
import org.smartdata.test.step.HmsStep;
import org.smartdata.test.step.LoginStep;
import org.smartdata.test.step.MenuStep;
import org.smartdata.test.step.PaginationStep;
import org.smartdata.test.step.RulesStep;
import org.smartdata.test.step.TableStep;
import org.smartdata.test.suite.SsmWebBaseSuite;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.sql.DataSource;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.ACTION;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.STATUS;
import static org.smartdata.test.element.PaginationElement.PageSize.THIRTY;
import static org.smartdata.test.model.ActionStatus.SUCCESSFUL;
import static org.smartdata.test.model.SsmComponent.TARGET_NAMENODE;

@Feature("HMS")
@RequiredComponents(TARGET_NAMENODE)
public class HmsSyncRuleWebTestSuite extends SsmWebBaseSuite {
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
  private HmsStep hmsStep;
  @Autowired
  private ActionsStep actionsStep;
  @Autowired
  private ActionsDetailsStep actionsDetailsStep;
  @Autowired
  private ApiStep apiStep;
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
  public void restoreEnv() throws IOException {
    hmsStep.restoreEnv(true);
  }

  @BeforeMethod(dependsOnMethods = "restoreEnv")
  public void testPrepare() {
    loginStep.loginAs(UserRole.OWNER);
    menuStep.openRulesPage();
  }

  @TmsLink("136492")
  @Story("HMS Sync entities")
  @Test(description = "Check HMS rule and actions")
  public void testHmsRuleAndActions() {
    rulesStep.createRule(format(HMS_SYNC_RULE_TEMPLATE, TEST_DATABASE_2))
        .startRuleInFirstRow();
    dataBaseStep.prepareDataForHmsRulesAndActionsTest();
    menuStep.openActionsPage();
    paginationStep.setShowPerPageOption(THIRTY);
    checkSuccessSyncActions(19, TEST_DATABASE_2);
  }

  @TmsLink("136575")
  @Story("HMS Sync entities")
  @Test(description = "Check HMS rule for constraints")
  public void testHmsRuleForConstraints() {
    prepareRuleAndDataFixture(
        format(HMS_SYNC_RULE_TEMPLATE, TEST_DATABASE_1), String.join("\n",
            "CREATE DATABASE db1;",
            "CREATE TABLE db1.students (id INT, name STRING NOT NULL, email STRING DEFAULT 'unknown');"));
    checkSuccessSyncActions(4, TEST_DATABASE_1);
    assertHivesConstraintsEquals(TEST_DATABASE_1, "students", 2);
    sqlExecutor.executeSql(hiveServer2DataSource, String.join("\n",
        "ALTER TABLE db1.students ADD CONSTRAINT students_pk PRIMARY KEY (id) DISABLE NOVALIDATE;",
        "CREATE TABLE db1.students_data (data_id INT, student_id INT);",
        "ALTER TABLE db1.students_data ADD CONSTRAINT students_data_fk FOREIGN KEY (student_id) REFERENCES db1.students(id) DISABLE NOVALIDATE;"));
    checkSuccessSyncActions(7, TEST_DATABASE_1);
    assertHivesConstraintsEquals(TEST_DATABASE_1, "students", 3);
    assertHivesConstraintsEquals(TEST_DATABASE_1, "students_data", 1);
    sqlExecutor.executeSql(hiveServer2DataSource, String.join("\n",
        "ALTER TABLE db1.students_data DROP CONSTRAINT students_data_fk;",
        "ALTER TABLE db1.students DROP CONSTRAINT students_pk;"));
    checkSuccessSyncActions(9, TEST_DATABASE_1);
    assertHivesConstraintsEquals(TEST_DATABASE_1, "students", 2);
    assertHivesConstraintsEquals(TEST_DATABASE_1, "students_data", 0);
  }

  @TmsLink("136571")
  @Story("HMS Sync entities")
  @Test(description = "Check HMS rule for databases")
  public void testHmsRuleForDatabases() {
    prepareRuleAndDataFixture(
        format(HMS_SYNC_RULE_TEMPLATE, TEST_DATABASE_1),
        "CREATE DATABASE db1;");
    checkSuccessSyncActions(1, TEST_DATABASE_1);
    assertHivesDatabaseParametersEquals(TEST_DATABASE_1, "");
    sqlExecutor.executeSql(hiveServer2DataSource, "ALTER DATABASE db1 SET DBPROPERTIES ('Date' = '2026-01-13');");
    checkSuccessSyncActions(2, TEST_DATABASE_1);
    assertHivesDatabaseParametersEquals(TEST_DATABASE_1, "{Date=2026-01-13}");
    sqlExecutor.executeSql(hiveServer2DataSource, "DROP DATABASE db1;");
    checkSuccessSyncActions(3, TEST_DATABASE_1);
    assertHivesDatabasesDoNotContain(TEST_DATABASE_1);
    sqlExecutor.executeSql(hiveServer2DataSource, String.join("\n",
        "CREATE DATABASE db1;",
        "CREATE TABLE db1.t1 (id INT);",
        "DROP DATABASE db1 CASCADE;"));
    checkSuccessSyncActions(7, TEST_DATABASE_1);
  }

  @TmsLink("136574")
  @Story("HMS Sync entities")
  @Test(description = "Check HMS rule for functions")
  public void testHmsRuleForFunctions() {
    prepareRuleAndDataFixture(
        format(HMS_SYNC_RULE_TEMPLATE, TEST_DATABASE_1),
        "CREATE DATABASE db1;");
    checkSuccessSyncActions(1, TEST_DATABASE_1);
    sqlExecutor.executeSql(hiveServer2DataSource,
        "CREATE FUNCTION db1.sum_cols AS 'org.apache.hadoop.hive.ql.udf.generic.GenericUDFOPPlus';");
    checkSuccessSyncActions(2, TEST_DATABASE_1);
    sqlExecutor.executeSql(targetHiveServer2DataSource, "RELOAD FUNCTION;");
    assertFunctionResultEquals("SELECT db1.sum_cols(1,3)", "4");
    sqlExecutor.executeSql(hiveServer2DataSource, "DROP FUNCTION db1.sum_cols;");
    checkSuccessSyncActions(3, TEST_DATABASE_1);
    sqlExecutor.executeSql(targetHiveServer2DataSource, "RELOAD FUNCTION;");
    assertHivesFunctionsDoNotContain("sum_cols");
  }

  @TmsLink("136573")
  @Story("HMS Sync entities")
  @Test(description = "Check HMS rule for partitions")
  public void testHmsRuleForPartitions() {
    prepareRuleAndDataFixture(
        format(HMS_SYNC_RULE_TEMPLATE, TEST_DATABASE_1), String.join("\n",
            "CREATE DATABASE db1;",
            "CREATE TABLE db1.clients (id INT, name STRING) PARTITIONED BY (month STRING);",
            "ALTER TABLE db1.clients ADD PARTITION (month='december');"));
    checkSuccessSyncActions(3, TEST_DATABASE_1);
    assertHivesPartitionsEquals("db1.clients", "month=december");
    sqlExecutor.executeSql(hiveServer2DataSource,
        "ALTER TABLE db1.clients PARTITION (month='december') RENAME TO PARTITION (month='january');");
    checkSuccessSyncActions(4, TEST_DATABASE_1);
    assertHivesPartitionsEquals("db1.clients", "month=january");
    sqlExecutor.executeSql(hiveServer2DataSource,
        "ALTER TABLE db1.clients DROP PARTITION (month='january');");
    checkSuccessSyncActions(5, TEST_DATABASE_1);
    assertHivesPartitionsEmpty("db1.clients");
  }

  @TmsLink("136572")
  @Story("HMS Sync entities")
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
    prepareRuleAndDataFixture(
        format(HMS_SYNC_RULE_TEMPLATE, TEST_DATABASE_1), String.join("\n",
            "CREATE DATABASE db1;",
            "CREATE TABLE db1.t1 (i INT);"));
    checkSuccessSyncActions(2, TEST_DATABASE_1);
    assertHivesTableColumnsEqual("db1.t1", Collections.singletonList(colI));
    sqlExecutor.executeSql(hiveServer2DataSource, "ALTER TABLE db1.t1 ADD COLUMNS (j STRING);");
    checkSuccessSyncActions(3, TEST_DATABASE_1);
    assertHivesTableColumnsEqual("db1.t1", Arrays.asList(colJ, colI));
    sqlExecutor.executeSql(hiveServer2DataSource, "DROP TABLE db1.t1");
    checkSuccessSyncActions(4, TEST_DATABASE_1);
    assertHivesTablesDoNotContain("db1", "t1");
  }

  @TmsLink("136243")
  @Story("HMS Sync entities")
  @Test(description = "Check HMS rule actions logs")
  public void testHmsRuleActionsLogs() {
    List<ActionLogCase> actionLogCases = Arrays.asList(
        new ActionLogCase(
            "CREATE DATABASE db1;",
            1,
            "Creating database db1",
            "Database was successfully created"),
        new ActionLogCase(
            "ALTER DATABASE db1 SET DBPROPERTIES ('Date' = '2026-01-13');",
            2,
            "Altering database db1",
            "Database was successfully altered"),
        new ActionLogCase(
            "CREATE TABLE db1.clients (id INT, name STRING) PARTITIONED BY (MONTH STRING);",
            3,
            "Creating table db1.clients",
            "Table was successfully created"),
        new ActionLogCase(
            "ALTER TABLE db1.clients ADD COLUMNS (i INT);",
            4,
            "Altering table db1.clients",
            "Table was successfully altered"),
        new ActionLogCase(
            "ALTER TABLE db1.clients ADD PARTITION (MONTH='december');",
            5,
            "Creating partitions for table clients",
            "partition: [december]",
            "Partitions were successfully created"),
        new ActionLogCase(
            "ALTER TABLE db1.clients PARTITION (MONTH ='december') RENAME TO PARTITION (MONTH ='january');",
            6,
            "Altering partition [december] for table db1.clients",
            "Partitions was successfully altered"),
        new ActionLogCase(
            "ALTER TABLE db1.clients DROP PARTITION (MONTH='january');",
            7,
            "Dropping partition for table db1.clients",
            "Dropping partition: [january]",
            "Partitions were successfully dropped"),
        new ActionLogCase(
            "ALTER TABLE db1.clients ADD CONSTRAINT clients_pk PRIMARY KEY (id) DISABLE NOVALIDATE;",
            8,
            "Creating primary key",
            "Constraint was successfully created"),
        new ActionLogCase(
            "ALTER TABLE db1.clients DROP CONSTRAINT clients_pk;",
            9,
            "Dropping constraint clients_pk for table db1.clients",
            "Constraint was successfully dropped"),
        new ActionLogCase(
            "CREATE FUNCTION db1.sum_cols AS 'org.apache.hadoop.hive.ql.udf.generic.GenericUDFOPPlus';",
            10,
            "Creating function db1.sum_cols",
            "Function was successfully created"),
        new ActionLogCase(
            "DROP FUNCTION db1.sum_cols;",
            11,
            "Dropping function db1.sum_cols",
            "Function was successfully dropped"),
        new ActionLogCase(
            "DROP TABLE db1.clients;",
            12,
            "Dropping table db1.clients",
            "Table was successfully dropped"),
        new ActionLogCase(
            "DROP DATABASE db1;",
            13,
            "Dropping database db1",
            "Database was successfully dropped"));
    apiStep.createAndStartRule(format(HMS_SYNC_RULE_TEMPLATE, TEST_DATABASE_1));
    menuStep.openActionsPage();
    paginationStep.setShowPerPageOption(THIRTY);
    for (ActionLogCase actionLogCase : actionLogCases) {
      executeSqlAndCheckLatestActionLog(actionLogCase);
    }
  }

  @Step("Execute SQL and verify latest action log")
  private void executeSqlAndCheckLatestActionLog(ActionLogCase actionLogCase) {
    sqlExecutor.executeSql(hiveServer2DataSource, actionLogCase.sql);
    menuStep.openActionsPage();
    checkSuccessSyncActions(actionLogCase.expectedActionsCount, TEST_DATABASE_1);
    actionsStep.openFirstActionDetails();
    actionsDetailsStep.openActionDetailsLog()
        .checkActionDetailsLogContainsTexts(actionLogCase.expectedLogTexts);
  }

  @Step("Prepare HMS rule and test data fixture")
  private void prepareRuleAndDataFixture(String rule, String sql) {
    rulesStep.createRule(rule)
        .startRuleInFirstRow();
    sqlExecutor.executeSql(hiveServer2DataSource, sql);
    menuStep.openActionsPage();
    tableStep.setRefreshingFrequency(1);
  }

  @Step("Check successful sync actions for entity '{entityName}' has size {expectedSize}")
  private void checkSuccessSyncActions(int expectedSize, String entityName) {
    tableStep.checkTableRowsCountIs(expectedSize)
        .checkAllColumnCellsContain(expectedSize, ACTION, format("-entityName %s", entityName))
        .checkAllColumnCellsTextEqual(expectedSize, STATUS, SUCCESSFUL.getText());
  }

  @Step("Assert both hives constraints are equal for table '{database}.{table}' with expected size {expectedSize}")
  private void assertHivesConstraintsEquals(String database, String table, int expectedSize) {
    List<Map<String, Object>> sourceConstraints =
        dataBaseStep.getTableConstraints(hiveServer2DataSource, database, table);
    List<Map<String, Object>> targetConstraints =
        dataBaseStep.getTableConstraints(targetHiveServer2DataSource, database, table);
    assertThat(targetConstraints).hasSize(expectedSize).containsExactlyInAnyOrderElementsOf(sourceConstraints);
  }

  @Step("Assert both hives database '{database}' parameters equal '{expectedParameters}'")
  private void assertHivesDatabaseParametersEquals(String database, String expectedParameters) {
    assertThat(dataBaseStep.getDatabaseParameters(hiveServer2DataSource, database)).singleElement()
        .isEqualTo(expectedParameters);
    assertThat(dataBaseStep.getDatabaseParameters(targetHiveServer2DataSource, database)).singleElement()
        .isEqualTo(expectedParameters);
  }

  @Step("Assert both hives do not contain database '{database}'")
  private void assertHivesDatabasesDoNotContain(String database) {
    assertThat(dataBaseStep.getDatabases(hiveServer2DataSource)).isNotEmpty().doesNotContain(database);
    assertThat(dataBaseStep.getDatabases(targetHiveServer2DataSource)).isNotEmpty().doesNotContain(database);
  }

  @Step("Assert both hives function query result equals expected value")
  private void assertFunctionResultEquals(String query, String expectedResult) {
    assertThat(sqlExecutor.queryFirstColumnAsStrings(hiveServer2DataSource, query)).singleElement()
        .isEqualTo(expectedResult);
    assertThat(sqlExecutor.queryFirstColumnAsStrings(targetHiveServer2DataSource, query)).singleElement()
        .isEqualTo(expectedResult);
  }

  @Step("Assert both hives do not contain function '{functionName}'")
  private void assertHivesFunctionsDoNotContain(String functionName) {
    assertThat(dataBaseStep.getFunctions(hiveServer2DataSource)).doesNotContain(functionName);
    assertThat(dataBaseStep.getFunctions(targetHiveServer2DataSource)).doesNotContain(functionName);
  }

  @Step("Assert both hives partitions for table '{tableName}' equal '{expectedPartition}'")
  private void assertHivesPartitionsEquals(String tableName, String expectedPartition) {
    assertThat(dataBaseStep.getPartitions(hiveServer2DataSource, tableName)).singleElement()
        .isEqualTo(expectedPartition);
    assertThat(dataBaseStep.getPartitions(targetHiveServer2DataSource, tableName)).singleElement()
        .isEqualTo(expectedPartition);
  }

  @Step("Assert both hives partitions for table '{tableName}' are empty")
  private void assertHivesPartitionsEmpty(String tableName) {
    assertThat(dataBaseStep.getPartitions(hiveServer2DataSource, tableName)).isEmpty();
    assertThat(dataBaseStep.getPartitions(targetHiveServer2DataSource, tableName)).isEmpty();
  }

  @Step("Assert both hives table '{tableName}' columns equal expected columns")
  private void assertHivesTableColumnsEqual(String tableName, List<Map<String, Object>> expectedColumns) {
    assertThat(dataBaseStep.getTableColumnsWithParams(hiveServer2DataSource, tableName))
        .containsExactlyInAnyOrderElementsOf(expectedColumns);
    assertThat(dataBaseStep.getTableColumnsWithParams(targetHiveServer2DataSource, tableName))
        .containsExactlyInAnyOrderElementsOf(expectedColumns);
  }

  @Step("Assert both hives do not contain table '{database}.{tableName}'")
  private void assertHivesTablesDoNotContain(String database, String tableName) {
    assertThat(dataBaseStep.getTables(hiveServer2DataSource, database)).doesNotContain(tableName);
    assertThat(dataBaseStep.getTables(targetHiveServer2DataSource, database)).doesNotContain(tableName);
  }

  private static final class ActionLogCase {
    private final String sql;
    private final int expectedActionsCount;
    private final String[] expectedLogTexts;

    private ActionLogCase(String sql, int expectedActionsCount, String... expectedLogTexts) {
      this.sql = sql;
      this.expectedActionsCount = expectedActionsCount;
      this.expectedLogTexts = expectedLogTexts;
    }
  }
}
