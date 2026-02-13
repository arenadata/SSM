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
import io.qameta.allure.Story;
import io.qameta.allure.TmsLink;
import org.smartdata.test.dao.impl.HiveMetastoreEventDaoImpl;
import org.smartdata.test.dao.impl.HiveSyncProgressDaoImpl;
import org.smartdata.test.element.ActionsPageElement.ActionsTableColumn;
import org.smartdata.test.entity.HiveSyncProgressEntity;
import org.smartdata.test.service.ConfigModifierService;
import org.smartdata.test.step.ActionsStep;
import org.smartdata.test.step.DataBaseStep;
import org.smartdata.test.step.LoginStep;
import org.smartdata.test.step.MenuStep;
import org.smartdata.test.step.RulesStep;
import org.smartdata.test.step.TableStep;
import org.smartdata.test.suite.SsmWebBaseSuite;
import org.springframework.beans.factory.annotation.Autowired;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.time.Duration;

import static io.arenadata.test.model.UserRole.OWNER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.smartdata.test.model.ActionStatus.FAILED;
import static org.smartdata.test.model.ActionStatus.SUCCESSFUL;
import static org.smartdata.test.model.SsmComponent.SSM_SERVER;
import static org.smartdata.test.util.constant.CommonConstants.AGENT_CONF_NAME;
import static org.smartdata.test.util.constant.CommonConstants.MASTER_CONF_NAME;

@Feature("HMS replication")
public class HmsWebTestSuite extends SsmWebBaseSuite {
  private static final String TEST_DATABASE = "db1";
  private static final String HMS_SYNC_RULE =
      "hms : name matches \"*.*\" | hms-sync -dest thrift://target-hive-metastore:9083/ -cascade -nameservice_rename \"source target\"";
  private static final Duration AWAITILITY_PULL_INTERVAL = Duration.ofMillis(1000);
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
  private HiveMetastoreEventDaoImpl hiveMetastoreEventDao;
  @Autowired
  private HiveSyncProgressDaoImpl hiveSyncProgressDao;

  @BeforeMethod
  public void restoreEnv() throws IOException {
    containerManager.stop(SSM_SERVER);
    configModifierService.restoreOriginalFile(MASTER_CONF_NAME);
    configModifierService.restoreOriginalFile(AGENT_CONF_NAME);
    dataBaseStep.dropHiveServersTable(TEST_DATABASE)
        .truncateSsmHiveNotificationLogTable();
    hiveMetastoreEventDao.deleteAll();
    hiveSyncProgressDao.deleteAll();
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
    configModifierService.addProperty(MASTER_CONF_NAME,
        "smart.hive.sync.progress.flush.interval.ms", "65000");
    Duration timeoutBeforeSync = Duration.ofSeconds(35); // sync shouldn't be completed earlier
    Duration timeoutAfterSync = Duration.ofSeconds(80); // sync should be completed earlier
    checkHiveSyncProgressFlushIntervalFixture(timeoutBeforeSync, timeoutAfterSync);
  }

  private void checkHiveSyncProgressEntityInit(Duration timeout) {
    await().atMost(timeout)
        .pollInterval(AWAITILITY_PULL_INTERVAL)
        .untilAsserted(() -> assertThat(hiveSyncProgressDao.findAll())
            .singleElement()
            .extracting(HiveSyncProgressEntity::getEventId)
            .satisfies(eventId -> assertThat(eventId).isPositive()));
  }

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
    dataBaseStep.createHiveServerDatabase(TEST_DATABASE);
    checkHiveSyncProgressEventIdChanged(eventIdBeforeDbCreation, atLeast, atMost);
    actionsStep.refreshPage();
    tableStep.checkTableRowsCountIs(2)
        .checkColumnCellsContainsValues(ActionsTableColumn.STATUS, FAILED.getText(), SUCCESSFUL.getText());
  }
}
