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
import io.qameta.allure.TmsLinks;
import org.assertj.core.groups.Tuple;
import org.smartdata.test.dao.impl.HiveMetastoreEventDaoImpl;
import org.smartdata.test.entity.HiveMetastoreEventEntity;
import org.smartdata.test.entity.HiveMetastoreEventEntity.EntityType;
import org.smartdata.test.entity.HiveMetastoreEventEntity.EventType;
import org.smartdata.test.service.ConfigModifierService;
import org.smartdata.test.service.SqlExecutor;
import org.smartdata.test.step.DataBaseStep;
import org.smartdata.test.suite.SsmBaseSuite;
import org.smartdata.test.util.LogsUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.sql.DataSource;

import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static io.arenadata.test.util.Utils.waitUntil;
import static io.arenadata.test.util.constant.TimeoutConstants.DEFAULT_WAIT_PARAMS;
import static io.arenadata.test.util.constant.TimeoutConstants.EXTENDED_WAIT_PARAMS;
import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.awaitility.Awaitility.await;
import static org.smartdata.test.model.SsmComponent.SSM_SERVER;
import static org.smartdata.test.util.constant.CommonConstants.AGENT_CONF_NAME;
import static org.smartdata.test.util.constant.CommonConstants.MASTER_CONF_NAME;

@Feature("HMS replication")
public class HmsConfigTestSuite extends SsmBaseSuite {
  @Autowired
  private ConfigModifierService configModifierService;
  @Autowired
  private ContainerManager containerManager;
  private static final String EVENT_SYNC_FULL_PARAM = "smart.hive.event.sync.full";
  @Autowired
  private HiveMetastoreEventDaoImpl hiveMetastoreEventDao;
  @Autowired
  private DataBaseStep dataBaseStep;
  @Autowired
  private SqlExecutor sqlExecutor;
  @Autowired
  @Qualifier("hiveServer2DataSource")
  private DataSource hiveServer2DataSource;

  private static final String EVENT_FETCH_ENABLED_PARAM = "smart.hive.event.fetch.enabled";
  private static final String EVENT_FETCH_BATCH_SIZE_PARAM = "smart.hive.event.fetch.batch.size";
  private static final String DEFAULT_DATABASE = "default";
  private static final String TEST_DATABASE = "db1";
  private static final String EVENT_FETCH_PERIOD_MS_PARAM = "smart.hive.event.fetch.period.ms";
  private static final String EVENT_APPLIER_RETRY_STRATEGY_PARAM = "smart.hive.event.applier.retry.strategy";
  private static final String EVENT_APPLIER_RETRY_MAX_PARAM = "smart.hive.event.applier.retry.max";
  private static final String EVENT_APPLIER_RETRY_INTERVAL_MS_PARAM = "smart.hive.event.applier.retry.interval.ms";
  private static final String RETRY_STRATEGY_ERROR_MESSAGE =
      "TableMetaDataProvider [INFO] Unable to locate table meta-data for 'hive_metastore_event': column names must be provided";
  private static final String RETRY_STRATEGY_EXCEPTION_MESSAGE =
      "org.smartdata.retry.RetryException: retries get failed due to exceeded maximum allowed retries number: %s";
  private static final String RETRY_STRATEGY_FAIL_EXCEPTION_MESSAGE =
      "org.smartdata.retry.RetryException: try once and fail.";
  private static final Duration AWAITILITY_PULL_INTERVAL = Duration.ofMillis(1000);

  @BeforeMethod
  public void restoreEnv() throws IOException {
    containerManager.stop(SSM_SERVER);
    configModifierService.restoreOriginalFile(MASTER_CONF_NAME);
    configModifierService.restoreOriginalFile(AGENT_CONF_NAME);
    dataBaseStep.dropHiveServersTable(TEST_DATABASE)
        .truncateSsmHiveNotificationLogTable();
    hiveMetastoreEventDao.deleteAll();
  }

  @AfterMethod(onlyForGroups = "restoreHiveMetastoreEventTable")
  public void restoreHiveMetastoreEventTable() {
    dataBaseStep.restoreHiveMetastoreEventTable();
  }

  @TmsLink("136494")
  @Story("HMS Configuration")
  @Test(description = "Check smart.hive.event.sync.full=true")
  public void testHiveEventSyncFullTrue() throws Exception {
    configModifierService.addProperty(MASTER_CONF_NAME, EVENT_SYNC_FULL_PARAM, "true");
    List<Long> eventsIds = setupEventsIdsForSyncFullTests();
    containerManager.restart(SSM_SERVER);
    assertThat(hiveMetastoreEventDao.findAll())
        .extracting(HiveMetastoreEventEntity::getId)
        .doesNotContainAnyElementsOf(eventsIds);
  }

  @TmsLink("136493")
  @Story("HMS Configuration")
  @Test(description = "Check smart.hive.event.sync.full=false")
  public void testHiveEventSyncFullFalse() throws Exception {
    configModifierService.addProperty(MASTER_CONF_NAME, EVENT_SYNC_FULL_PARAM, "false");
    List<Long> eventsIds = setupEventsIdsForSyncFullTests();
    containerManager.restart(SSM_SERVER);
    assertThat(hiveMetastoreEventDao.findAll())
        .extracting(HiveMetastoreEventEntity::getId)
        .containsExactlyElementsOf(eventsIds);
  }

  private List<Long> setupEventsIdsForSyncFullTests() throws Exception {
    int testTableQuantity = 2;
    containerManager.start(SSM_SERVER);
    createTestDataInHiveMetaStore(testTableQuantity);
    checkEventsContainExpectedEntities(testTableQuantity);
    return hiveMetastoreEventDao.findAll().stream()
        .map(HiveMetastoreEventEntity::getId)
        .collect(Collectors.toList());
  }

  @TmsLink("136286")
  @Story("HMS Configuration")
  @Test(description = "Check smart.hive.event.fetch.enabled=true")
  public void testHiveEventFetchEnabledTrue() throws Exception {
    configModifierService.setProperty(MASTER_CONF_NAME, EVENT_FETCH_ENABLED_PARAM, "true");
    containerManager.start(SSM_SERVER);
    int testTableQuantity = 1;
    createTestDataInHiveMetaStore(testTableQuantity);
    checkEventsContainExpectedEntities(testTableQuantity);
  }

  @TmsLink("136285")
  @Story("HMS Configuration")
  @Test(description = "Check smart.hive.event.fetch.enabled=false")
  public void testHiveEventFetchEnabledFalse() throws Exception {
    configModifierService.setProperty(MASTER_CONF_NAME, EVENT_FETCH_ENABLED_PARAM, "false");
    containerManager.start(SSM_SERVER);
    int testTableQuantity = 1;
    createTestDataInHiveMetaStore(testTableQuantity);
    await().atMost(Duration.ofSeconds(30))
        .during(Duration.ofSeconds(10))
        .pollInterval(AWAITILITY_PULL_INTERVAL)
        .untilAsserted(() -> assertThat(hiveMetastoreEventDao.findAll()).isEmpty());
  }

  @TmsLinks({@TmsLink("136405"), @TmsLink("136406")})
  @Story("HMS Configuration")
  @Test(description = "Check smart.hive.event.fetch.period.ms (+ additional check for smart.hive.event.fetch.batch.size)")
  public void testHiveEventFetchPeriod() throws Exception {
    configModifierService.addProperty(MASTER_CONF_NAME, EVENT_FETCH_BATCH_SIZE_PARAM, "2");
    configModifierService.addProperty(MASTER_CONF_NAME, EVENT_FETCH_PERIOD_MS_PARAM, "30000");
    containerManager.start(SSM_SERVER);
    int testTableQuantity = 5;
    createTestDataInHiveMetaStore(testTableQuantity);
    Duration timeoutBeforeFetch = Duration.ofSeconds(25); // fetch shouldn't be completed earlier
    Duration timeoutAfterFetch = Duration.ofSeconds(35); // fetch should be completed earlier
    checkHiveMetastoreEventsHasSizeInPeriodOfTime(Duration.ofSeconds(0), timeoutAfterFetch, 3);
    checkHiveMetastoreEventsHasSizeInPeriodOfTime(timeoutBeforeFetch, timeoutAfterFetch, 5);
    checkHiveMetastoreEventsHasSizeInPeriodOfTime(timeoutBeforeFetch, timeoutAfterFetch, 7);
  }

  private void checkHiveMetastoreEventsHasSizeInPeriodOfTime(Duration atLeast, Duration atMost, int expectedSize) {
    await().atLeast(atLeast)
        .and()
        .atMost(atMost)
        .pollInterval(AWAITILITY_PULL_INTERVAL)
        .untilAsserted(() -> assertThat(hiveMetastoreEventDao.findAll()).hasSize(expectedSize));
  }

  @TmsLink("136351")
  @Story("HMS Configuration")
  @Test(description = "Check smart.hive.event.applier.retry.strategy=FAIL", groups = "restoreHiveMetastoreEventTable")
  public void testHiveEventApplierRetryStrategyFail() throws Exception {
    configModifierService.addProperty(MASTER_CONF_NAME, EVENT_APPLIER_RETRY_STRATEGY_PARAM, "FAIL");
    setupDataForRetryStrategyTests();
    checkRetryStrategyErrorLogsCount(1);
    waitUntil(() -> assertThat(containerManager.getContainerLogs(SSM_SERVER)).contains(
        RETRY_STRATEGY_FAIL_EXCEPTION_MESSAGE), EXTENDED_WAIT_PARAMS);
  }

  @TmsLink("136285")
  @Story("HMS Configuration")
  @Test(description = "Check smart.hive.event.applier.retry.strategy=EXPONENTIAL", groups = "restoreHiveMetastoreEventTable")
  public void testHiveEventApplierRetryStrategyExponential() throws Exception {
    configModifierService.addProperty(MASTER_CONF_NAME, EVENT_APPLIER_RETRY_STRATEGY_PARAM, "EXPONENTIAL");
    configModifierService.addProperty(MASTER_CONF_NAME, EVENT_APPLIER_RETRY_MAX_PARAM, "5");
    setupDataForRetryStrategyTests();
    checkRetryStrategyErrorLogsCount(5);
    checkRetryStrategyErrorTimeBetweenLogsExponential();
    waitUntil(() -> assertThat(containerManager.getContainerLogs(SSM_SERVER)).contains(
        format(RETRY_STRATEGY_EXCEPTION_MESSAGE, 5)), EXTENDED_WAIT_PARAMS);
  }

  @TmsLink("136350")
  @Story("HMS Configuration")
  @Test(description = "Check smart.hive.event.applier.retry.strategy=FIXED_SLEEP with default configs", groups = "restoreHiveMetastoreEventTable")
  public void testHiveEventApplierRetryStrategyFixedSleepDefault() throws Exception {
    configModifierService.addProperty(MASTER_CONF_NAME, EVENT_APPLIER_RETRY_STRATEGY_PARAM, "FIXED_SLEEP");
    setupDataForRetryStrategyTests();
    checkRetryStrategyErrorLogsCount(10);
    checkRetryStrategyErrorTimeBetweenLogsIs(Duration.ofSeconds(1));
    waitUntil(() -> assertThat(containerManager.getContainerLogs(SSM_SERVER)).contains(
        format(RETRY_STRATEGY_EXCEPTION_MESSAGE, 10)), EXTENDED_WAIT_PARAMS);
  }

  @TmsLink("136382")
  @Story("HMS Configuration")
  @Test(description = "Check smart.hive.event.applier.retry.strategy=FIXED_SLEEP with non-default smart.hive.event.applier.retry.interval.ms and smart.hive.event.applier.retry.max", groups = "restoreHiveMetastoreEventTable")
  public void testHiveEventApplierRetryStrategyFixedSleepNonDefault() throws Exception {
    configModifierService.addProperty(MASTER_CONF_NAME, EVENT_APPLIER_RETRY_STRATEGY_PARAM, "FIXED_SLEEP");
    configModifierService.addProperty(MASTER_CONF_NAME, EVENT_APPLIER_RETRY_INTERVAL_MS_PARAM, "4000");
    configModifierService.addProperty(MASTER_CONF_NAME, EVENT_APPLIER_RETRY_MAX_PARAM, "3");
    setupDataForRetryStrategyTests();
    checkRetryStrategyErrorLogsCount(3);
    checkRetryStrategyErrorTimeBetweenLogsIs(Duration.ofSeconds(4));
    waitUntil(() -> assertThat(containerManager.getContainerLogs(SSM_SERVER)).contains(
        format(RETRY_STRATEGY_EXCEPTION_MESSAGE, 3)), EXTENDED_WAIT_PARAMS);
  }

  private void setupDataForRetryStrategyTests() throws Exception {
    containerManager.start(SSM_SERVER);
    int testTableQuantity = 1;
    createTestDataInHiveMetaStore(testTableQuantity);
    waitUntil(() -> assertThat(hiveMetastoreEventDao.findAll()).hasSize(3), DEFAULT_WAIT_PARAMS);
    dataBaseStep.dropHiveMetastoreEventTable();
    sqlExecutor.executeSql(hiveServer2DataSource, "create table db1.t2(i int)");
  }

  private List<String> getRetryStrategyErrorLogs() {
    String logs = containerManager.getContainerLogs(SSM_SERVER);
    return LogsUtil.getLinesContainsText(logs, RETRY_STRATEGY_ERROR_MESSAGE);
  }

  private void checkRetryStrategyErrorLogsCount(int expectedCount) {
    waitUntil(() -> assertThat(getRetryStrategyErrorLogs()).hasSize(expectedCount), EXTENDED_WAIT_PARAMS);
  }

  private void checkRetryStrategyErrorTimeBetweenLogsIs(Duration durationBetweenLogs) {
    List<LocalDateTime> logsTime = LogsUtil.getTimeFromLines(getRetryStrategyErrorLogs());
    for (int i = 0; i < logsTime.size() - 1; i++) {
      Duration timeDiff = Duration.between(logsTime.get(i), logsTime.get(i + 1));
      assertThat(timeDiff).isEqualTo(durationBetweenLogs);
    }
  }

  private void checkRetryStrategyErrorTimeBetweenLogsExponential() {
    List<LocalDateTime> logsTime = LogsUtil.getTimeFromLines(getRetryStrategyErrorLogs());
    for (int i = 0; i < logsTime.size() - 2; i++) {
      Duration currentInterval = Duration.between(logsTime.get(i), logsTime.get(i + 1));
      Duration nextInterval = Duration.between(logsTime.get(i + 1), logsTime.get(i + 2));
      assertThat(nextInterval).satisfiesAnyOf(
          value -> assertThat(value).isGreaterThan(currentInterval),
          value -> assertThat(value).isCloseTo(currentInterval, Duration.ofSeconds(1))
      );
    }
  }

  private void createTestDataInHiveMetaStore(int testTableQuantity) throws Exception {
    sqlExecutor.executeSql(hiveServer2DataSource, "create database " + TEST_DATABASE);
    for (int i = 0; i < testTableQuantity; i++) {
      sqlExecutor.executeSql(hiveServer2DataSource, format("create table %s.t%s(i int)", TEST_DATABASE, i));
    }
  }

  private void checkEventsContainExpectedEntities(int testTableQuantity) {
    List<Tuple> expectedEvents = new ArrayList<>();
    expectedEvents.add(tuple(DEFAULT_DATABASE, EntityType.DATABASE.name(), EventType.CREATE.name()));
    expectedEvents.add(tuple(TEST_DATABASE, EntityType.DATABASE.name(), EventType.CREATE.name()));
    for (int i = 0; i < testTableQuantity; i++) {
      expectedEvents.add(
          tuple(format("%s.t%s", TEST_DATABASE, i), EntityType.TABLE.name(), EventType.CREATE.name()));
    }
    waitUntil(() -> assertThat(hiveMetastoreEventDao.findAll())
        .extracting(HiveMetastoreEventEntity::getEntityName,
            HiveMetastoreEventEntity::getEntityType,
            HiveMetastoreEventEntity::getEventType)
        .containsExactlyInAnyOrder(expectedEvents.toArray(new Tuple[0])), DEFAULT_WAIT_PARAMS);
  }
}
