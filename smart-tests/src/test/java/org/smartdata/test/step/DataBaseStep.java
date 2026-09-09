/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.smartdata.test.step;

import io.arenadata.test.util.FileUtils;
import io.qameta.allure.Step;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.smartdata.test.service.SqlExecutor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;

import java.nio.file.Paths;
import java.sql.PreparedStatement;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static java.time.temporal.ChronoUnit.HOURS;

@Slf4j
@Service
public class DataBaseStep {
  @Autowired
  private SqlExecutor sqlExecutor;
  @Autowired
  @Qualifier("ssmMetastoreDataSource")
  private DataSource ssmMetastoreDataSource;
  @Autowired
  @Qualifier("hiveServer2DataSource")
  private DataSource hiveServer2DataSource;
  @Autowired
  @Qualifier("ssmHiveDataSource")
  private DataSource ssmHiveDataSource;
  @Autowired(required = false)
  @Qualifier("targetHiveServer2DataSource")
  private DataSource targetHiveServer2DataSource;

  private static final String SHOW_DATABASES_SQL = "SHOW DATABASES";
  private static final String SHOW_FUNCTIONS_SQL = "SHOW FUNCTIONS";
  private static final String SHOW_PARTITIONS_TEMPLATE = "SHOW PARTITIONS %s";
  private static final String SHOW_TABLES_IN_DATABASE_TEMPLATE = "SHOW TABLES IN %s";
  private static final String DESCRIBE_DATABASE_EXTENDED_TEMPLATE = "DESCRIBE DATABASE EXTENDED %s";
  private static final String DESCRIBE_TABLE_TEMPLATE = "DESCRIBE %s";
  private static final String DESCRIBE_TABLE_EXTENDED_TEMPLATE = "DESCRIBE EXTENDED %s.%s";
  private static final String DROP_HIVE_SERVERS_TABLE_TEMPLATE = "DROP DATABASE IF EXISTS %s CASCADE";
  private static final String DROP_TABLE_TEMPLATE = "DROP TABLE %s";
  private static final String CREATE_DATABASE_TEMPLATE = "CREATE DATABASE %s";
  private static final String TRUNCATE_TABLE_TEMPLATE = "TRUNCATE TABLE %s;";
  private static final String RESET_RULE_SEQUENCE = "ALTER SEQUENCE rule_id_seq RESTART WITH 1;";
  private static final String RULES_FILTER_TEMPLATE = "INSERT INTO rule" +
                                                      "(\"name\", state, rule_text, submit_time, last_check_time, checked_count, generated_cmdlets, \"owner\") " +
                                                      "VALUES(NULL, ?, ?, ?, ?, 1, 1, 'john');";
  private static final String SQL_FOLDER_PATH = "src/test/resources/data/sql/";
  private static final String RULES_FOR_SORT_TEST_SQL = "insert_rules_for_sort_test.sql";
  private static final String ACTIONS_FOR_SORT_TEST_SQL = "insert_actions_for_sort_test.sql";
  private static final String ACTION_FOR_FILTER_TEST_SQL = "insert_action_for_filter_test.sql";
  private static final String ACTION_FOR_ACTION_DETAILS_PAGE_TEST_SQL =
      "insert_action_for_action_details_page_test.sql";
  private static final String AUDIT_FOR_SORT_TEST_SQL = "insert_audit_for_sort_test.sql";
  private static final String AUDIT_FOR_FILTER_TEST_SQL = "insert_audit_for_filter_test.sql";
  private static final String INSERT_HOTTEST_FILES_SQL = "insert_fake_hottest_files.sql";
  private static final String DELETE_HOTTEST_FILES_SQL = "delete_hottest_files_table.sql";
  private static final String HOTTEST_FILES_FOR_PAGINATION_TEST_SQL = "insert_hottest_files_for_pagination_test.sql";
  private static final String INSERT_FILES_IN_CACHE_SQL = "insert_fake_files_in_cache.sql";
  private static final String FILES_IN_CACHE_FOR_PAGINATION_TEST_SQL = "insert_files_in_cache_for_pagination_test.sql";
  private static final String RESTORE_HIVE_METASTORE_EVENT_TABLE_SQL = "restore_hive_metastore_event_table.sql";
  private static final String PREPARE_DATA_HMS_RULES_AND_ACTIONS_SQL = "prepare_data_for_hms_rule_and_actions_test.sql";
  private static final String PREPARE_DATA_HMS_FETCHED_EVENTS_SQL = "prepare_data_for_hms_fetched_events_test.sql";

  @Step("Clean 'rule' table")
  public DataBaseStep cleanRuleTable() {
    sqlExecutor.executeSql(ssmMetastoreDataSource, format(TRUNCATE_TABLE_TEMPLATE, "rule"));
    sqlExecutor.executeSql(ssmMetastoreDataSource, RESET_RULE_SEQUENCE);
    return this;
  }

  @Step("Clean 'action' table")
  public DataBaseStep cleanActionTable() {
    sqlExecutor.executeSql(ssmMetastoreDataSource, format(TRUNCATE_TABLE_TEMPLATE, "action"));
    return this;
  }

  @Step("Clean 'user_activity_event' table")
  public DataBaseStep cleanAuditTable() {
    sqlExecutor.executeSql(ssmMetastoreDataSource, format(TRUNCATE_TABLE_TEMPLATE, "user_activity_event"));
    return this;
  }

  @Step("Clean hottest files table")
  public DataBaseStep cleanHottestFilesTable() {
    sqlExecutor.executeSqlFile(ssmMetastoreDataSource, getSqlFilePath(DELETE_HOTTEST_FILES_SQL));
    return this;
  }

  @Step("Clean 'cached_file' table")
  public DataBaseStep cleanFilesInCacheTable() {
    sqlExecutor.executeSql(ssmMetastoreDataSource, format(TRUNCATE_TABLE_TEMPLATE, "cached_file"));
    return this;
  }

  @Step("Clean all UI tables")
  public DataBaseStep cleanAllUiTables() {
    cleanRuleTable()
        .cleanActionTable()
        .cleanAuditTable()
        .cleanHottestFilesTable()
        .cleanFilesInCacheTable();
    return this;
  }

  @Step("Insert data for rules sorting test")
  public DataBaseStep insertDataForRulesSortTest() {
    sqlExecutor.executeSqlFile(ssmMetastoreDataSource, getSqlFilePath(RULES_FOR_SORT_TEST_SQL));
    return this;
  }

  @SneakyThrows
  @Step("Insert data for rules filtration test")
  public DataBaseStep insertDataForRulesFilterTest() {
    String firstRule = "file: every 1s | path matches \"/*\" | sleep -ms 100";
    String secondRule = "file: every 1s | path matches \"/*\" | read";
    try (PreparedStatement ps = ssmMetastoreDataSource.getConnection().prepareStatement(RULES_FILTER_TEMPLATE)) {
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

  @Step("Insert data for actions sorting test")
  public DataBaseStep insertDataForActionSortTest() {
    sqlExecutor.executeSqlFile(ssmMetastoreDataSource, getSqlFilePath(ACTIONS_FOR_SORT_TEST_SQL));
    return this;
  }

  @Step("Insert data for actions filtration test")
  public DataBaseStep insertDataForActionFilterTest() {
    sqlExecutor.executeSqlFile(ssmMetastoreDataSource, getSqlFilePath(ACTION_FOR_FILTER_TEST_SQL));
    return this;
  }

  @Step("Insert data for Action Details page test")
  public DataBaseStep insertDataForActionDetailsPageTest() {
    sqlExecutor.executeSqlFile(ssmMetastoreDataSource, getSqlFilePath(ACTION_FOR_ACTION_DETAILS_PAGE_TEST_SQL));
    return this;
  }

  @Step("Insert data for audit sorting test")
  public DataBaseStep insertDataForAuditSortTest() {
    sqlExecutor.executeSqlFile(ssmMetastoreDataSource, getSqlFilePath(AUDIT_FOR_SORT_TEST_SQL));
    return this;
  }

  @Step("Insert data for audit filtration test")
  public DataBaseStep insertDataForAuditFilterTest() {
    sqlExecutor.executeSqlFile(ssmMetastoreDataSource, getSqlFilePath(AUDIT_FOR_FILTER_TEST_SQL));
    return this;
  }

  @Step("Insert fake data for hottest files test")
  public DataBaseStep insertFakeDataForHottestFilesTest() {
    String sql = FileUtils.readFile(getSqlFilePath(INSERT_HOTTEST_FILES_SQL));
    sql = sql.replace("${currentTime}", String.valueOf(Instant.now().toEpochMilli()));
    sqlExecutor.executeSql(ssmMetastoreDataSource, sql);
    return this;
  }

  @Step("Insert data for hottest files pagination test with file path '{filePath}'")
  public DataBaseStep insertDataForHottestFilesPaginationTest(String filePath) {
    String sql = FileUtils.readFile(getSqlFilePath(HOTTEST_FILES_FOR_PAGINATION_TEST_SQL));
    sql = sql.replace("${filePath}", filePath);
    sql = sql.replace("${currentTime}", String.valueOf(Instant.now().toEpochMilli()));
    sqlExecutor.executeSql(ssmMetastoreDataSource, sql);
    return this;
  }

  @Step("Insert fake data for files in cache test")
  public DataBaseStep insertFakeDataForFilesInCacheTest() {
    String sql = FileUtils.readFile(getSqlFilePath(INSERT_FILES_IN_CACHE_SQL));
    sql = sql.replace("${currentTime}", String.valueOf(Instant.now().toEpochMilli()));
    sqlExecutor.executeSql(ssmMetastoreDataSource, sql);
    return this;
  }

  @Step("Insert data for files in cache pagination test with file id '{fileId}'")
  public DataBaseStep insertDataForFilesInCachePaginationTest(String fileId) {
    String sql = FileUtils.readFile(getSqlFilePath(FILES_IN_CACHE_FOR_PAGINATION_TEST_SQL));
    sql = sql.replace("${fileId}", fileId);
    sqlExecutor.executeSql(ssmMetastoreDataSource, sql);
    return this;
  }

  @Step("Create source Hive database '{tableName}'")
  public DataBaseStep createHiveServerDatabase(String tableName) {
    sqlExecutor.executeSql(hiveServer2DataSource, format(CREATE_DATABASE_TEMPLATE, tableName));
    return this;
  }

  @Step("Drop all Hive databases except default on both Hive instances")
  public DataBaseStep dropHiveServersTablesExceptDefault() {
    dropDatabasesExceptDefault(hiveServer2DataSource);
    dropDatabasesExceptDefault(targetHiveServer2DataSource);
    return this;
  }

  @Step("Truncate SSM Hive NOTIFICATION_LOG table")
  public DataBaseStep truncateSsmHiveNotificationLogTable() {
    sqlExecutor.executeSql(ssmHiveDataSource, format(TRUNCATE_TABLE_TEMPLATE, "\"NOTIFICATION_LOG\""));
    return this;
  }

  @Step("Drop 'hive_metastore_event' table")
  public DataBaseStep dropHiveMetastoreEventTable() {
    sqlExecutor.executeSql(ssmMetastoreDataSource, format(DROP_TABLE_TEMPLATE, "hive_metastore_event"));
    return this;
  }

  @Step("Restore 'hive_metastore_event' table")
  public DataBaseStep restoreHiveMetastoreEventTable() {
    sqlExecutor.executeSqlFile(ssmMetastoreDataSource, getSqlFilePath(RESTORE_HIVE_METASTORE_EVENT_TABLE_SQL));
    return this;
  }

  @Step("Prepare data for HMS rules and actions test")
  public DataBaseStep prepareDataForHmsRulesAndActionsTest() {
    sqlExecutor.executeSqlFile(hiveServer2DataSource, getSqlFilePath(PREPARE_DATA_HMS_RULES_AND_ACTIONS_SQL));
    return this;
  }

  @Step("Prepare data for HMS fetched events test")
  public DataBaseStep prepareDataForHmsFetchedEventsTest() {
    sqlExecutor.executeSqlFile(hiveServer2DataSource, getSqlFilePath(PREPARE_DATA_HMS_FETCHED_EVENTS_SQL));
    return this;
  }

  @Step("Get databases from data source")
  public List<String> getDatabases(DataSource dataSource) {
    return sqlExecutor.queryFirstColumnAsStrings(dataSource, SHOW_DATABASES_SQL);
  }

  @Step("Get parameters of database '{databaseName}'")
  public List<String> getDatabaseParameters(DataSource dataSource, String databaseName) {
    return sqlExecutor.queryByColumnAsStrings(dataSource,
        format(DESCRIBE_DATABASE_EXTENDED_TEMPLATE, databaseName),
        "parameters");
  }

  @Step("Get tables from database '{databaseName}'")
  public List<String> getTables(DataSource dataSource, String databaseName) {
    return sqlExecutor.queryFirstColumnAsStrings(dataSource, format(SHOW_TABLES_IN_DATABASE_TEMPLATE, databaseName));
  }

  @Step("Get functions from data source")
  public List<String> getFunctions(DataSource dataSource) {
    return sqlExecutor.queryFirstColumnAsStrings(dataSource, SHOW_FUNCTIONS_SQL);
  }

  @Step("Get partitions for table '{tableName}'")
  public List<String> getPartitions(DataSource dataSource, String tableName) {
    return sqlExecutor.queryFirstColumnAsStrings(dataSource, format(SHOW_PARTITIONS_TEMPLATE, tableName));
  }

  @Step("Get columns with params for table '{tableName}'")
  public List<Map<String, Object>> getTableColumnsWithParams(DataSource dataSource, String tableName) {
    return sqlExecutor.queryForList(dataSource, format(DESCRIBE_TABLE_TEMPLATE, tableName))
        .stream()
        .filter(row -> row.get("col_name") != null && !row.get("col_name").toString().trim().isEmpty())
        .collect(Collectors.toList());
  }

  @Step("Get constraints for table '{databaseName}.{tableName}'")
  public List<Map<String, Object>> getTableConstraints(DataSource dataSource, String databaseName, String tableName) {
    return sqlExecutor.queryForList(dataSource, format(DESCRIBE_TABLE_EXTENDED_TEMPLATE, databaseName, tableName))
        .stream()
        .filter(row -> row.get("col_name") != null
                       && row.get("col_name").toString().toLowerCase().contains("constraint"))
        .collect(Collectors.toList());
  }

  private String getSqlFilePath(String fileName) {
    return Paths.get(SQL_FOLDER_PATH, fileName).toString();
  }

  private void dropDatabasesExceptDefault(DataSource dataSource) {
    getDatabases(dataSource).stream()
        .filter(databaseName -> !"default".equalsIgnoreCase(databaseName))
        .forEach(databaseName -> sqlExecutor.executeSql(dataSource,
            format(DROP_HIVE_SERVERS_TABLE_TEMPLATE, databaseName)));
  }
}
