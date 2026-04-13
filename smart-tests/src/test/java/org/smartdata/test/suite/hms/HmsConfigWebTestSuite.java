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

import io.arenadata.test.service.ContainerManager;
import io.qameta.allure.Feature;
import io.qameta.allure.Step;
import io.qameta.allure.Story;
import io.qameta.allure.TmsLink;
import org.smartdata.test.annotation.RequiredComponents;
import org.smartdata.test.dao.impl.HiveSyncProgressDaoImpl;
import org.smartdata.test.element.ActionsPageElement.ActionsTableColumn;
import org.smartdata.test.entity.HiveSyncProgressEntity;
import org.smartdata.test.service.ConfigModifierService;
import org.smartdata.test.service.SqlExecutor;
import org.smartdata.test.step.ActionsStep;
import org.smartdata.test.step.ApiStep;
import org.smartdata.test.step.DataBaseStep;
import org.smartdata.test.step.HmsStep;
import org.smartdata.test.step.LoginStep;
import org.smartdata.test.step.MenuStep;
import org.smartdata.test.step.RulesStep;
import org.smartdata.test.step.TableStep;
import org.smartdata.test.suite.SsmWebBaseSuite;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.sql.DataSource;

import java.io.IOException;
import java.time.Duration;

import static io.arenadata.test.model.UserRole.OWNER;
import static io.arenadata.test.util.Utils.waitUntil;
import static io.arenadata.test.util.constant.TimeoutConstants.DEFAULT_WAIT_PARAMS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.smartdata.test.model.ActionStatus.FAILED;
import static org.smartdata.test.model.ActionStatus.SUCCESSFUL;
import static org.smartdata.test.model.SsmComponent.SSM_SERVER;
import static org.smartdata.test.model.SsmComponent.TARGET_NAMENODE;
import static org.smartdata.test.util.constant.CommonConstants.MASTER_CONF_NAME;

@Feature("HMS")
@RequiredComponents(TARGET_NAMENODE)
public class HmsConfigWebTestSuite extends SsmWebBaseSuite {
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
  private DataBaseStep dataBaseStep;
  @Autowired
  private HmsStep hmsStep;
  @Autowired
  private ApiStep apiStep;
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
  private static final String SYNC_PROGRESS_FLUSH_INTERVAL_PARAM = "smart.hive.sync.progress.flush.interval.ms";
  private static final String EVENT_INCLUDE_PATTERNS_PARAM = "smart.hive.event.include.patterns";
  private static final String EVENT_IGNORE_PATTERNS_PARAM = "smart.hive.event.ignore.patterns";
  private static final String HMS_SYNC_RULE =
      "hms : name matches \"*.*\" | hms-sync -dest thrift://target-hive-metastore:9083/ -cascade -nameservice_rename \"source target\"";
  private static final Duration AWAITILITY_PULL_INTERVAL = Duration.ofMillis(1000);

  @BeforeMethod
  public void restoreEnv() throws IOException {
    hmsStep.restoreEnv(false);
  }

  @TmsLink("136403")
  @Story("HMS Configuration")
  @Test(description = "Check smart.hive.sync.progress.flush.interval.ms default config 5000ms")
  public void testHiveSyncProgressFlushIntervalDefault() {
    Duration timeoutBeforeSync = Duration.ofSeconds(2); // sync shouldn't be completed earlier
    Duration timeoutAfterSync = Duration.ofSeconds(20); // sync should be completed earlier
    checkHiveSyncProgressFlushIntervalFixture(timeoutBeforeSync, timeoutAfterSync);
  }

  @TmsLink("136410")
  @Story("HMS Configuration")
  @Test(description = "Check smart.hive.sync.progress.flush.interval.ms non-default config")
  public void testHiveSyncProgressFlushIntervalNonDefault() throws IOException {
    configModifierService.addProperty(MASTER_CONF_NAME, SYNC_PROGRESS_FLUSH_INTERVAL_PARAM, "65000");
    Duration timeoutBeforeSync = Duration.ofSeconds(35); // sync shouldn't be completed earlier
    Duration timeoutAfterSync = Duration.ofSeconds(80); // sync should be completed earlier
    checkHiveSyncProgressFlushIntervalFixture(timeoutBeforeSync, timeoutAfterSync);
  }

  @TmsLink("136247")
  @Story("HMS Configuration")
  @Test(description = "Check smart.hive.event.include.patterns and smart.hive.event.ignore.patterns")
  public void testHiveEventIncludeAndIgnorePatterns() throws Exception {
    configModifierService.addProperty(MASTER_CONF_NAME, EVENT_INCLUDE_PATTERNS_PARAM, "db1,db1\\.t.*");
    configModifierService.addProperty(MASTER_CONF_NAME, EVENT_IGNORE_PATTERNS_PARAM, ".*tb23.*");
    containerManager.start(SSM_SERVER);
    sqlExecutor.executeSql(hiveServer2DataSource, String.join("\n",
        "CREATE DATABASE db1;",
        "CREATE TABLE db1.tb1(i INT);",
        "CREATE TABLE db1.tb23(i INT);"));
    assertNoDatabasesSyncedBeforeRule(TEST_DATABASE_1);
    startRuleAndWaitTablesOnTargetHive(TEST_DATABASE_1, "tb1");
    loginStep.loginAs(OWNER);
    menuStep.openActionsPage();
    hmsStep.checkSuccessSyncActions(2, TEST_DATABASE_1);
  }

  @TmsLink("136262")
  @Story("HMS Configuration")
  @Test(description = "Check smart.hive.event.include.patterns")
  public void testHiveEventIncludePatterns() throws Exception {
    configModifierService.addProperty(MASTER_CONF_NAME, EVENT_INCLUDE_PATTERNS_PARAM, "db1,db1\\.t.*");
    containerManager.start(SSM_SERVER);
    sqlExecutor.executeSql(hiveServer2DataSource, String.join("\n",
        "CREATE DATABASE db1;",
        "CREATE TABLE db1.tb1(i INT);",
        "CREATE TABLE db1.t1(i INT);",
        "CREATE DATABASE db2;",
        "CREATE TABLE db2.tb1(i INT);"));
    assertNoDatabasesSyncedBeforeRule(TEST_DATABASE_1, TEST_DATABASE_2);
    startRuleAndWaitTablesOnTargetHive(TEST_DATABASE_1, "t1", "tb1");
    loginStep.loginAs(OWNER);
    menuStep.openActionsPage();
    hmsStep.checkSuccessSyncActions(3, TEST_DATABASE_1);
  }

  @TmsLink("136245")
  @Story("HMS Configuration")
  @Test(description = "Check smart.hive.event.ignore.patterns")
  public void testHiveEventIgnorePatterns() throws Exception {
    configModifierService.addProperty(MASTER_CONF_NAME, EVENT_IGNORE_PATTERNS_PARAM, "db1.tb.*,db2.*");
    containerManager.start(SSM_SERVER);
    sqlExecutor.executeSql(hiveServer2DataSource, String.join("\n",
        "CREATE DATABASE db1;",
        "CREATE TABLE db1.tb1(i INT);",
        "CREATE TABLE db1.t1(i INT);",
        "CREATE DATABASE db2;",
        "CREATE TABLE db2.tb1(i INT);",
        "CREATE TABLE db2.t1(i INT);"));
    assertNoDatabasesSyncedBeforeRule(TEST_DATABASE_1, TEST_DATABASE_2);
    startRuleAndWaitTablesOnTargetHive(TEST_DATABASE_1, "t1");
    loginStep.loginAs(OWNER);
    menuStep.openActionsPage();
    tableStep.checkTableRowsCountIs(3)
        .checkColumnCellsContainsValues(ActionsTableColumn.STATUS,
            FAILED.getText(), SUCCESSFUL.getText(), SUCCESSFUL.getText());
  }

  @Step("Check HiveSyncProgress entity initialized within timeout {timeout}")
  private void checkHiveSyncProgressEntityInit(Duration timeout) {
    await().atMost(timeout)
        .pollInterval(AWAITILITY_PULL_INTERVAL)
        .untilAsserted(() -> assertThat(hiveSyncProgressDao.findAll())
            .singleElement()
            .extracting(HiveSyncProgressEntity::getEventId)
            .satisfies(eventId -> assertThat(eventId).isPositive()));
  }

  @Step("Check HiveSyncProgress event id changed from {idBeforeChange} in period between {atLeast} and {atMost}")
  private void checkHiveSyncProgressEventIdChanged(Long idBeforeChange, Duration atLeast, Duration atMost) {
    await().atLeast(atLeast)
        .and()
        .atMost(atMost)
        .pollInterval(AWAITILITY_PULL_INTERVAL)
        .untilAsserted(() -> assertThat(hiveSyncProgressDao.findAll())
            .singleElement()
            .extracting(HiveSyncProgressEntity::getEventId)
            .isEqualTo(idBeforeChange + 1));
  }

  @Step("Fixture check HiveSyncProgress flush interval in period between {atLeast} and {atMost}")
  private void checkHiveSyncProgressFlushIntervalFixture(Duration atLeast, Duration atMost) {
    containerManager.start(SSM_SERVER);
    assertThat(hiveSyncProgressDao.findAll()).isEmpty();
    loginStep.loginAs(OWNER);
    menuStep.openRulesPage();
    rulesStep.createRule(HMS_SYNC_RULE)
        .startRuleInFirstRow();
    menuStep.openActionsPage();
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(ActionsTableColumn.STATUS, FAILED.getText());
    checkHiveSyncProgressEntityInit(atMost);
    Long eventIdBeforeDbCreation = hiveSyncProgressDao.findAll().get(0).getEventId();
    dataBaseStep.createHiveServerDatabase(TEST_DATABASE_1);
    checkHiveSyncProgressEventIdChanged(eventIdBeforeDbCreation, atLeast, atMost);
    actionsStep.refreshPage();
    tableStep.checkTableRowsCountIs(2)
        .checkColumnCellsContainsValues(ActionsTableColumn.STATUS, FAILED.getText(), SUCCESSFUL.getText());
  }

  @Step("Check no databases synced before rule: dbNames={dbNames}")
  private void assertNoDatabasesSyncedBeforeRule(String... dbNames) {
    await().during(Duration.ofSeconds(15))
        .atMost(Duration.ofSeconds(20))
        .untilAsserted(
            () -> assertThat(dataBaseStep.getDatabases(targetHiveServer2DataSource)).doesNotContain(dbNames));
  }

  @Step("Start Sync rule and wait tables on target hive: db={database}, tables={expectedTables}")
  private void startRuleAndWaitTablesOnTargetHive(String database, String... expectedTables) {
    apiStep.createAndStartRule(HMS_SYNC_RULE);
    waitUntil(() -> assertThat(dataBaseStep.getTables(targetHiveServer2DataSource, database)).contains(expectedTables),
        DEFAULT_WAIT_PARAMS);
  }
}
