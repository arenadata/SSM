package org.smartdata.test.suite.hms;

import io.arenadata.test.service.ContainerManager;
import io.qameta.allure.Feature;
import io.qameta.allure.Story;
import io.qameta.allure.TmsLink;
import org.smartdata.test.dao.impl.HiveMetastoreEventDaoImpl;
import org.smartdata.test.dao.impl.HiveSyncProgressDaoImpl;
import org.smartdata.test.entity.HiveMetastoreEventEntity;
import org.smartdata.test.service.SqlExecutor;
import org.smartdata.test.step.ApiStep;
import org.smartdata.test.step.DataBaseStep;
import org.smartdata.test.suite.SsmBaseSuite;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import javax.sql.DataSource;

import java.util.HashMap;
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

@Feature("HMS")
public class HmsStatsReplicationTestSuite extends SsmBaseSuite {
  @Autowired
  private ContainerManager containerManager;
  @Autowired
  private DataBaseStep dataBaseStep;
  @Autowired
  private ApiStep apiStep;
  @Autowired
  private HiveMetastoreEventDaoImpl hiveMetastoreEventDao;
  @Autowired
  private HiveSyncProgressDaoImpl hiveSyncProgressDao;
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
  @Autowired
  @Qualifier("targetHiveServer2DataSource")
  private DataSource targetHiveServer2DataSource;

  private static final String TEST_DATABASE_1 = "db1";
  private static final String TEST_RULE =
      "hms : name matches \"db1.*\" | hms-sync -dest thrift://target-hive-metastore:9083/ -cascade -nameservice_rename \"source target\"";

  @AfterMethod
  public void restoreEnv() {
    apiStep.deleteAllRules();
    containerManager.stop(SSM_SERVER);
    dataBaseStep.dropHiveServersTable(TEST_DATABASE_1)
        .truncateSsmHiveNotificationLogTable();
    hiveMetastoreEventDao.deleteAll();
    hiveSyncProgressDao.deleteAll();
    containerManager.start(SSM_SERVER);
  }

  @TmsLink("136053")
  @Story("HMS stats replication")
  @Test(description = "Check HMS stats replication")
  public void testHmsStatsReplication() {
    sqlExecutor.executeSql(hiveServer2DataSource, "create database db1;\n" +
        "create table db1.t1(i int);\n" +
        "insert into db1.t1 values (1), (2), (3);\n" +
        "analyze table db1.t1 compute statistics for columns;");
    List<Map<String, Object>> sourceTabColStats = sqlExecutor.queryForList(ssmHiveDataSource, "SELECT * FROM \"TAB_COL_STATS\"");
    assertThat(sourceTabColStats)
        .singleElement()
        .satisfies(row -> assertThat(row)
            .containsEntry("DB_NAME", "db1")
            .containsEntry("TABLE_NAME", "t1")
            .containsEntry("COLUMN_NAME", "i")
            .containsEntry("COLUMN_TYPE", "int"));

    List<Map<String, Object>> targetTabColStats = sqlExecutor.queryForList(ssmHive2DataSource, "SELECT * FROM \"TAB_COL_STATS\"");
    assertThat(targetTabColStats).isEmpty();

    apiStep.createAndStartRule(TEST_RULE);

    waitUntil(() -> assertThat(sqlExecutor.queryForList(ssmHive2DataSource, "SELECT * FROM \"TAB_COL_STATS\""))
          .singleElement()
          .satisfies(row -> {
            Map<String, Object> sourceRow = new HashMap<>(sourceTabColStats.get(0));
            Map<String, Object> targetRow = new HashMap<>(row);
            sourceRow.remove("LAST_ANALYZED");
            targetRow.remove("LAST_ANALYZED");
            assertThat(targetRow)
                .usingRecursiveComparison()
                .isEqualTo(sourceRow);
          }), DEFAULT_WAIT_PARAMS);
  }

  @TmsLink("136054")
  @Story("HMS stats replication")
  @Test(description = "Check HMS stats replication with snapshot phase")
  public void testHmsStatsReplicationWithSnapshotPhase() {
    sqlExecutor.executeSql(hiveServer2DataSource, "create database db1;\n" +
        "create table db1.t1(i int);\n" +
        "insert into db1.t1 values (1), (2), (3);\n" +
        "analyze table db1.t1 compute statistics for columns;");
    List<Map<String, Object>> sourceTabColStats = sqlExecutor.queryForList(ssmHiveDataSource, "SELECT * FROM \"TAB_COL_STATS\"");
    assertThat(sourceTabColStats)
        .singleElement()
        .satisfies(row -> assertThat(row)
            .containsEntry("DB_NAME", "db1")
            .containsEntry("TABLE_NAME", "t1")
            .containsEntry("COLUMN_NAME", "i")
            .containsEntry("COLUMN_TYPE", "int"));

    List<Map<String, Object>> targetTabColStats = sqlExecutor.queryForList(ssmHive2DataSource, "SELECT * FROM \"TAB_COL_STATS\"");
    assertThat(targetTabColStats).isEmpty();


    waitUntil(() -> assertThat(hiveMetastoreEventDao.findAll())
        .extracting(
            HiveMetastoreEventEntity::getEventType,
            HiveMetastoreEventEntity::getEntityName,
            HiveMetastoreEventEntity::getEntityType,
            HiveMetastoreEventEntity::getDbName,
            HiveMetastoreEventEntity::getTableName)
        .containsExactlyInAnyOrder(
            tuple(CREATE.name(), "default", DATABASE.name(), "default", null),
            tuple(CREATE.name(), "db1", DATABASE.name(), "db1", null),
            tuple(CREATE.name(), "db1.t1", TABLE.name(), "db1", "t1"),
            tuple(ALTER.name(), "db1.t1", TABLE.name(), "db1", "t1"),
            tuple(ALTER.name(), "db1.t1", TABLE.name(), "db1", "t1"),
            tuple(ALTER.name(), "db1.t1", TABLE_COLUMN_STAT.name(), "db1", "t1"),
            tuple(ALTER.name(), "db1.t1", TABLE.name(), "db1", "t1"),
            tuple(ALTER.name(), "db1.t1", TABLE_COLUMN_STAT.name(), "db1", "t1")
        ), DEFAULT_WAIT_PARAMS);

    containerManager.stop(SSM_SERVER);
    hiveMetastoreEventDao.deleteAll();
    containerManager.start(SSM_SERVER);

    waitUntil(() -> assertThat(hiveMetastoreEventDao.findAll())
        .extracting(
            HiveMetastoreEventEntity::getEventType,
            HiveMetastoreEventEntity::getEntityName,
            HiveMetastoreEventEntity::getEntityType,
            HiveMetastoreEventEntity::getDbName,
            HiveMetastoreEventEntity::getTableName)
        .containsExactlyInAnyOrder(
            tuple(CREATE.name(), "default", DATABASE.name(), "default", null),
            tuple(CREATE.name(), "db1", DATABASE.name(), "db1", null),
            tuple(CREATE.name(), "db1.t1", TABLE.name(), "db1", "t1")
        ), DEFAULT_WAIT_PARAMS);

    apiStep.createAndStartRule(TEST_RULE);

    waitUntil(() -> assertThat(sqlExecutor.queryForList(ssmHive2DataSource, "SELECT * FROM \"TAB_COL_STATS\""))
        .singleElement()
        .satisfies(row -> {
          Map<String, Object> sourceRow = new HashMap<>(sourceTabColStats.get(0));
          Map<String, Object> targetRow = new HashMap<>(row);
          sourceRow.remove("LAST_ANALYZED");
          targetRow.remove("LAST_ANALYZED");
          sourceRow.remove("BIT_VECTOR");
          targetRow.remove("BIT_VECTOR");
          assertThat(targetRow)
              .usingRecursiveComparison()
              .isEqualTo(sourceRow);
        }), DEFAULT_WAIT_PARAMS);
  }
}
