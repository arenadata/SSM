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
import lombok.SneakyThrows;
import org.smartdata.test.dao.impl.HiveMetastoreEventDaoImpl;
import org.smartdata.test.dao.impl.HiveSyncProgressDaoImpl;
import org.smartdata.test.service.ConfigModifierService;
import org.smartdata.test.service.SqlExecutor;
import org.smartdata.test.step.ActionsStep;
import org.smartdata.test.step.ApiStep;
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
import org.testng.annotations.Test;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.time.Duration;
import java.util.ArrayList;
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
  private ConfigModifierService configModifierService;
  @Autowired
  private ContainerManager containerManager;
  @Autowired
  private LoginStep loginStep;
  @Autowired
  private MenuStep menuStep;
  @Autowired
  private RulesStep rulesStep;
  @Autowired
  private ActionsStep actionsStep;
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
  private static final Duration AWAITILITY_PULL_INTERVAL = Duration.ofMillis(1000);
  private static final String PREPARE_DATA_SQL =
      "/home/alehp/git/SSM/smart-tests/src/test/resources/data/sql/prepare_data_for_hms_rule_and_actions_test.sql";

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
    prepareDataForHmsRuleAndActionsTest();
    menuStep.openActionsPage();
    paginationStep.setShowPerPageOption(THIRTY, null);
    checkSuccessSyncActions(19, TEST_DATABASE_2);
  }

  private void prepareDataForHmsRuleAndActionsTest() {
    sqlExecutor.executeSqlFile(hiveServer2DataSource, PREPARE_DATA_SQL);
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

  private void checkSuccessSyncActions(int expectedSize, String database) {
    tableStep.checkTableRowsCountIs(expectedSize)
        .checkAllColumnCellsContain(expectedSize, ACTION, format("-entityName %s", database))
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

  @SneakyThrows
  private void checkDatabaseIsNotExist(DataSource dataSource, String database) {
    List<String> databases = new ArrayList<>();
    ResultSet rs = dataSource.getConnection().getMetaData().getCatalogs();
    while (rs.next()) {
      databases.add(rs.getString("TABLE_CAT").toLowerCase());
    }
    assertThat(databases).doesNotContain(database);
  }
}
