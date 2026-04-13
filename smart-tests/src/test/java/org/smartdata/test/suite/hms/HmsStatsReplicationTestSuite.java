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
import org.assertj.core.groups.Tuple;
import org.smartdata.test.annotation.RequiredComponents;
import org.smartdata.test.dao.impl.HiveMetastoreEventDaoImpl;
import org.smartdata.test.entity.HiveMetastoreEventEntity;
import org.smartdata.test.service.SqlExecutor;
import org.smartdata.test.step.ApiStep;
import org.smartdata.test.step.HmsStep;
import org.smartdata.test.suite.SsmBaseSuite;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.sql.DataSource;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static io.arenadata.test.util.Utils.waitUntil;
import static io.arenadata.test.util.constant.TimeoutConstants.DEFAULT_WAIT_PARAMS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.smartdata.test.entity.HiveMetastoreEventEntity.EntityType.DATABASE;
import static org.smartdata.test.entity.HiveMetastoreEventEntity.EntityType.TABLE;
import static org.smartdata.test.entity.HiveMetastoreEventEntity.EntityType.TABLE_COLUMN_STAT;
import static org.smartdata.test.entity.HiveMetastoreEventEntity.EventType.ALTER;
import static org.smartdata.test.entity.HiveMetastoreEventEntity.EventType.CREATE;
import static org.smartdata.test.model.SsmComponent.SSM_SERVER;
import static org.smartdata.test.model.SsmComponent.TARGET_NAMENODE;

@Feature("HMS")
@RequiredComponents(TARGET_NAMENODE)
public class HmsStatsReplicationTestSuite extends SsmBaseSuite {
  @Autowired
  private ContainerManager containerManager;
  @Autowired
  private ApiStep apiStep;
  @Autowired
  private HmsStep hmsStep;
  @Autowired
  private HiveMetastoreEventDaoImpl hiveMetastoreEventDao;
  @Autowired
  private SqlExecutor sqlExecutor;
  @Autowired
  @Qualifier("ssmHiveDataSource")
  private DataSource ssmHiveDataSource;
  @Autowired
  @Qualifier("ssmHive2DataSource")
  private DataSource ssmHive2DataSource;
  @Autowired
  @Qualifier("hiveServer2DataSource")
  private DataSource hiveServer2DataSource;

  private static final String TEST_RULE =
      "hms : name matches \"db1.*\" | hms-sync -dest thrift://target-hive-metastore:9083/ -cascade -nameservice_rename \"source target\"";
  private static final String TEST_DATABASE = "db1";
  private static final String TEST_TABLE = "t1";
  private static final String TEST_COLUMN = "i";
  private static final String TAB_COL_STATS_QUERY = "SELECT * FROM \"TAB_COL_STATS\"";
  private static final String LAST_ANALYZED_FIELD = "LAST_ANALYZED";
  private static final String BIT_VECTOR_FIELD = "BIT_VECTOR";
  private static final String PREPARE_STATS_SQL = String.join("\n",
      "CREATE DATABASE db1;",
      "CREATE TABLE db1.t1(i int);",
      "INSERT INTO db1.t1 VALUES (1), (2), (3);",
      "ANALYZE TABLE db1.t1 COMPUTE STATISTICS FOR COLUMNS;");
  private static final Tuple[] EVENTS_BEFORE_RESTART = {
      tuple(CREATE.name(), "default", DATABASE.name(), "default", null),
      tuple(CREATE.name(), "db1", DATABASE.name(), "db1", null),
      tuple(CREATE.name(), "db1.t1", TABLE.name(), "db1", "t1"),
      tuple(ALTER.name(), "db1.t1", TABLE.name(), "db1", "t1"),
      tuple(ALTER.name(), "db1.t1", TABLE.name(), "db1", "t1"),
      tuple(ALTER.name(), "db1.t1", TABLE_COLUMN_STAT.name(), "db1", "t1"),
      tuple(ALTER.name(), "db1.t1", TABLE.name(), "db1", "t1"),
      tuple(ALTER.name(), "db1.t1", TABLE_COLUMN_STAT.name(), "db1", "t1")
  };
  private static final Tuple[] EVENTS_WITH_SNAPSHOT_PHASE = {
      tuple(CREATE.name(), "default", DATABASE.name(), "default", null),
      tuple(CREATE.name(), "db1", DATABASE.name(), "db1", null),
      tuple(CREATE.name(), "db1.t1", TABLE.name(), "db1", "t1")
  };

  @BeforeMethod
  public void restoreEnv() throws IOException {
    hmsStep.restoreEnv(true);
  }

  @TmsLink("136053")
  @Story("HMS Stats replication")
  @Test(description = "Check HMS stats replication")
  public void testHmsStatsReplication() {
    createColumnStatsInSourceHive();
    Map<String, Object> sourceStatsRow = getAndAssertSourceTabColStatsRow();
    assertTargetStatsIsEmpty();
    apiStep.createAndStartRule(TEST_RULE);
    waitTabColStatsEqualIgnoringFields(sourceStatsRow, LAST_ANALYZED_FIELD);
  }

  @TmsLink("136054")
  @Story("HMS Stats replication")
  @Test(description = "Check HMS stats replication with snapshot phase")
  public void testHmsStatsReplicationWithSnapshotPhase() {
    createColumnStatsInSourceHive();
    Map<String, Object> sourceStatsRow = getAndAssertSourceTabColStatsRow();
    assertTargetStatsIsEmpty();
    waitForMetastoreEvents(EVENTS_BEFORE_RESTART);
    restartSsmWithEmptyMetastoreEvents();
    waitForMetastoreEvents(EVENTS_WITH_SNAPSHOT_PHASE);
    apiStep.createAndStartRule(TEST_RULE);
    waitTabColStatsEqualIgnoringFields(sourceStatsRow, LAST_ANALYZED_FIELD, BIT_VECTOR_FIELD);
  }

  @Step("Create source Hive database/table and compute column stats")
  private void createColumnStatsInSourceHive() {
    sqlExecutor.executeSql(hiveServer2DataSource, PREPARE_STATS_SQL);
  }

  @Step("Get TAB_COL_STATS rows")
  private List<Map<String, Object>> getTabColStats(DataSource dataSource) {
    return sqlExecutor.queryForList(dataSource, TAB_COL_STATS_QUERY);
  }

  @Step("Get and validate source TAB_COL_STATS row")
  private Map<String, Object> getAndAssertSourceTabColStatsRow() {
    List<Map<String, Object>> sourceTabColStats = getTabColStats(ssmHiveDataSource);
    assertThat(sourceTabColStats)
        .singleElement()
        .satisfies(row -> assertThat(row)
            .containsEntry("DB_NAME", TEST_DATABASE)
            .containsEntry("TABLE_NAME", TEST_TABLE)
            .containsEntry("COLUMN_NAME", TEST_COLUMN)
            .containsEntry("COLUMN_TYPE", "int"));
    return sourceTabColStats.get(0);
  }

  @Step("Assert target TAB_COL_STATS is empty")
  private void assertTargetStatsIsEmpty() {
    assertThat(getTabColStats(ssmHive2DataSource)).isEmpty();
  }

  @Step("Wait assert both TAB_COL_STATS rows are equal ignoring fields {fieldsToIgnore}")
  private void waitTabColStatsEqualIgnoringFields(Map<String, Object> sourceStatsRow, String... fieldsToIgnore) {
    waitUntil(() -> assertThat(getTabColStats(ssmHive2DataSource))
        .singleElement()
        .satisfies(row -> {
          Arrays.stream(fieldsToIgnore).forEach(field -> {
            sourceStatsRow.remove(field);
            row.remove(field);
          });
          assertThat(row)
              .usingRecursiveComparison()
              .isEqualTo(sourceStatsRow);
        }), DEFAULT_WAIT_PARAMS);
  }

  @Step("Wait for Hive metastore events to match expected set")
  private void waitForMetastoreEvents(Tuple... expectedEvents) {
    waitUntil(() -> assertThat(hiveMetastoreEventDao.findAll())
        .extracting(
            HiveMetastoreEventEntity::getEventType,
            HiveMetastoreEventEntity::getEntityName,
            HiveMetastoreEventEntity::getEntityType,
            HiveMetastoreEventEntity::getDbName,
            HiveMetastoreEventEntity::getTableName)
        .containsExactlyInAnyOrder(expectedEvents), DEFAULT_WAIT_PARAMS);
  }

  @Step("Restart SSM server with empty Hive metastore events")
  private void restartSsmWithEmptyMetastoreEvents() {
    containerManager.stop(SSM_SERVER);
    hiveMetastoreEventDao.deleteAll();
    containerManager.start(SSM_SERVER);
  }
}
