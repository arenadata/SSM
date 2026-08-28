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

import io.qameta.allure.Feature;
import io.qameta.allure.Step;
import io.qameta.allure.Story;
import io.restassured.response.Response;
import org.eclipse.jetty.http.HttpStatus;
import org.smartdata.client.generated.model.SubmitRuleRequestDto;
import org.smartdata.test.annotation.RequiredComponents;
import org.smartdata.test.service.SqlExecutor;
import org.smartdata.test.step.ApiStep;
import org.smartdata.test.step.DataBaseStep;
import org.smartdata.test.step.HdfsStep;
import org.smartdata.test.step.MenuStep;
import org.smartdata.test.step.TableStep;
import org.smartdata.test.suite.SsmBaseSuite;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.sql.DataSource;

import java.util.Arrays;
import java.util.List;

import static io.arenadata.test.util.Utils.waitUntil;
import static io.arenadata.test.util.constant.TimeoutConstants.EXTENDED_WAIT_PARAMS;
import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.smartdata.test.model.SsmComponent.HADOOP_NAMENODE;
import static org.smartdata.test.model.SsmComponent.TARGET_NAMENODE;

@Feature("HDFS")
@RequiredComponents({HADOOP_NAMENODE, TARGET_NAMENODE})
public class HdfsSyncRuleFilterEventsTestSuite extends SsmBaseSuite {
  @Autowired
  private HdfsStep hdfsStep;
  @Autowired
  private ApiStep apiStep;
  @Autowired
  private MenuStep menuStep;
  @Autowired
  private TableStep tableStep;
  @Autowired
  private DataBaseStep dataBaseStep;
  @Autowired
  private SqlExecutor sqlExecutor;
  @Autowired
  @Qualifier("ssmMetastoreDataSource")
  private DataSource ssmMetastoreDataSource;

  private static final String SOURCE_DIR = "/data";
  private static final String TARGET_FS_URI = "hdfs://target-namenode.demo:8020";
  private static final String SYNC_RULE_TEMPLATE =
      "file: path matches \"" + SOURCE_DIR + "/test/*\" | sync -dest "
      + TARGET_FS_URI + SOURCE_DIR + "/test/";
  private static final String PARALLEL_SYNC_RULE_TEMPLATE =
      "file: path matches \"" + SOURCE_DIR + "/%s/*\" | sync -dest "
      + TARGET_FS_URI + SOURCE_DIR + "/%s/";

  private static final String F1 = "file1";
  private static final String F2 = "file2";
  private static final String F3 = "file3";
  private static final String F1_RENAMED = "file1_renamed";
  private static final String F2_RENAMED = "file2_renamed";
  private static final String F3_RENAMED = "file3_renamed";
  private static final String F1_CONTENT = "one";
  private static final String F1_APPENDED_CONTENT = "onetwo";
  private static final String F2_CONTENT = "two";
  private static final String F2_APPENDED_CONTENT = "twomore";
  private static final String F3_CONTENT = "three";
  private static final String DEFAULT_PERMISSIONS = "644";
  private static final String CHANGED_PERMISSIONS = "777";
  private static final String APPENDED_PART = "two";
  private static final String APPENDED_PART_2 = "more";

  @BeforeMethod
  public void cleanHdfs() {
    apiStep.deleteAllRules();
    dataBaseStep.cleanActionTable();
    hdfsStep.delete(HADOOP_NAMENODE, SOURCE_DIR);
    hdfsStep.delete(TARGET_NAMENODE, SOURCE_DIR);
    hdfsStep.createDirectory(HADOOP_NAMENODE, SOURCE_DIR);
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check 'safe-copy' scenario: all events except DELETE")
  public void testSyncExcludeDelete() {
    apiStep.createAndStartRule(buildRule(null, "DELETE"));
    hdfsStep.createFile(HADOOP_NAMENODE, path(F1), F1_CONTENT);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(F1), APPENDED_PART);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(F1), CHANGED_PERMISSIONS);
    waitUntilSynced(path(F1), F1_APPENDED_CONTENT);
    waitUntilPermissionsSynced(path(F1), CHANGED_PERMISSIONS);
    hdfsStep.delete(HADOOP_NAMENODE, path(F1));
    createAndAwaitSync(F2, F2_CONTENT);
    checkNoActionWithName("delete");
    hdfsStep.checkFileExists(TARGET_NAMENODE, path(F1));
    hdfsStep.checkFileContent(TARGET_NAMENODE, path(F1), F1_APPENDED_CONTENT);
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check all types separately: CREATE")
  public void testSyncIncludeCreateOnly() {
    apiStep.createAndStartRule(buildRule("CREATE", null));
    createAndAwaitSync(F1, F1_CONTENT);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(F1), APPENDED_PART);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(F1), CHANGED_PERMISSIONS);
    hdfsStep.rename(HADOOP_NAMENODE, path(F1), path(F1_RENAMED));
    createAndAwaitSync(F2, F2_CONTENT);
    checkNoActionWithName("rename", "metadata");
    hdfsStep.checkFileContent(TARGET_NAMENODE, path(F1), F1_CONTENT);
    hdfsStep.checkPermissions(TARGET_NAMENODE, path(F1), DEFAULT_PERMISSIONS);
    hdfsStep.checkFileNotExists(TARGET_NAMENODE, path(F1_RENAMED));
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check all types separately: DELETE")
  public void testSyncIncludeDeleteOnly() {
    apiStep.createAndStartRule(buildRule("DELETE", null));
    seedFileOnBothClusters(F1, F1_CONTENT);
    hdfsStep.delete(HADOOP_NAMENODE, path(F1));
    waitUntilDeletedOnTarget(path(F1));
    hdfsStep.createFile(HADOOP_NAMENODE, path(F2), F2_CONTENT);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(F2), APPENDED_PART_2);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(F2), CHANGED_PERMISSIONS);
    hdfsStep.rename(HADOOP_NAMENODE, path(F2), path(F2_RENAMED));
    seedFileOnBothClusters(F3, F3_CONTENT);
    hdfsStep.delete(HADOOP_NAMENODE, path(F3));
    waitUntilDeletedOnTarget(path(F3));
    checkNoActionWithName("copy", "rename", "metadata");
    hdfsStep.checkFileNotExists(TARGET_NAMENODE, path(F2));
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check all types separately: RENAME")
  public void testSyncIncludeRenameOnly() {
    apiStep.createAndStartRule(buildRule("RENAME", null));
    seedFileOnBothClusters(F1, F1_CONTENT);
    hdfsStep.rename(HADOOP_NAMENODE, path(F1), path(F1_RENAMED));
    waitUntilSynced(path(F1_RENAMED), F1_CONTENT);
    waitUntilDeletedOnTarget(path(F1));
    seedFileOnBothClusters(F2, F2_CONTENT);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(F2), APPENDED_PART_2);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(F2), CHANGED_PERMISSIONS);
    hdfsStep.delete(HADOOP_NAMENODE, path(F2));
    seedFileOnBothClusters(F3, F3_CONTENT);
    hdfsStep.rename(HADOOP_NAMENODE, path(F3), path(F3_RENAMED));
    waitUntilSynced(path(F3_RENAMED), F3_CONTENT);
    waitUntilDeletedOnTarget(path(F3));
    checkNoActionWithName("copy", "metadata", "delete");
    hdfsStep.checkFileContent(TARGET_NAMENODE, path(F2), F2_CONTENT);
    hdfsStep.checkPermissions(TARGET_NAMENODE, path(F2), DEFAULT_PERMISSIONS);
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check all types separately: APPEND")
  public void testSyncIncludeAppendOnly() {
    apiStep.createAndStartRule(buildRule("APPEND", null));
    hdfsStep.createFile(HADOOP_NAMENODE, path(F1), F1_CONTENT);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(F1), APPENDED_PART);
    waitUntilSynced(path(F1), F1_APPENDED_CONTENT);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(F1), CHANGED_PERMISSIONS);
    hdfsStep.rename(HADOOP_NAMENODE, path(F1), path(F1_RENAMED));
    hdfsStep.delete(HADOOP_NAMENODE, path(F1_RENAMED));
    hdfsStep.createFile(HADOOP_NAMENODE, path(F2), F2_CONTENT);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(F2), APPENDED_PART_2);
    waitUntilSynced(path(F2), F2_APPENDED_CONTENT);
    checkNoActionWithName("rename", "metadata", "delete");
    hdfsStep.checkFileContent(TARGET_NAMENODE, path(F1), F1_APPENDED_CONTENT);
    hdfsStep.checkPermissions(TARGET_NAMENODE, path(F1), DEFAULT_PERMISSIONS);
    hdfsStep.checkFileNotExists(TARGET_NAMENODE, path(F1_RENAMED));
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check all types separately: METADATA")
  public void testSyncIncludeMetadataOnly() {
    apiStep.createAndStartRule(buildRule("METADATA", null));
    seedFileOnBothClusters(F1, F1_CONTENT);
    seedFileOnBothClusters(F2, F2_CONTENT);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(F1), CHANGED_PERMISSIONS);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(F2), APPENDED_PART_2);
    hdfsStep.rename(HADOOP_NAMENODE, path(F2), path(F2_RENAMED));
    hdfsStep.delete(HADOOP_NAMENODE, path(F2_RENAMED));
    seedFileOnBothClusters(F3, F3_CONTENT);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(F3), CHANGED_PERMISSIONS);
    waitUntilPermissionsSynced(path(F3), CHANGED_PERMISSIONS);
    waitUntilPermissionsSynced(path(F1), CHANGED_PERMISSIONS);
    checkNoActionWithName("copy", "rename", "delete");
    hdfsStep.checkFileContent(TARGET_NAMENODE, path(F1), F1_CONTENT);
    hdfsStep.checkFileNotExists(TARGET_NAMENODE, path(F2_RENAMED));
    hdfsStep.checkFileExists(TARGET_NAMENODE, path(F2));
    hdfsStep.checkFileContent(TARGET_NAMENODE, path(F2), F2_CONTENT);
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check multi-param -include CREATE,DELETE")
  public void testSyncIncludeCreateAndDelete() {
    apiStep.createAndStartRule(buildRule("CREATE,DELETE", null));
    createAndAwaitSync(F1, F1_CONTENT);
    createAndAwaitSync(F2, F2_CONTENT);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(F1), APPENDED_PART);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(F1), CHANGED_PERMISSIONS);
    hdfsStep.rename(HADOOP_NAMENODE, path(F2), path(F2_RENAMED));
    hdfsStep.delete(HADOOP_NAMENODE, path(F1));
    waitUntilDeletedOnTarget(path(F1));
    createAndAwaitSync(F3, F3_CONTENT);
    checkNoActionWithName("rename", "metadata");
    hdfsStep.checkFileContent(TARGET_NAMENODE, path(F2), F2_CONTENT);
    hdfsStep.checkFileNotExists(TARGET_NAMENODE, path(F2_RENAMED));
  }

//  @Story("HDFS Sync rule filtering events")
//  @Test(description = "Check duplicate param -include CREATE,CREATE")
//  public void testSyncIncludeDuplicateCreate() {
//    apiStep.createAndStartRule(buildRule("CREATE,CREATE", null));
//    createAndAwaitSync(F1, F1_CONTENT);
//    waitUntilActionsCountIs(1);
//    menuStep.openActionsPage();
//    tableStep.setRefreshingFrequency(1);
//    tableStep.checkTableRowsCountIs(1);
//    hdfsStep.checkFileContent(TARGET_NAMENODE, path(F1), F1_CONTENT);
//  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check params case insensitive -include Create,delete")
  public void testSyncIncludeCaseInsensitive() {
    apiStep.createAndStartRule(buildRule("Create,delete", null));
    createAndAwaitSync(F1, F1_CONTENT);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(F1), CHANGED_PERMISSIONS);
    hdfsStep.delete(HADOOP_NAMENODE, path(F1));
    waitUntilDeletedOnTarget(path(F1));
    createAndAwaitSync(F2, F2_CONTENT);
    checkNoActionWithName("metadata");
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check include priority -include CREATE,RENAME -exclude RENAME")
  public void testSyncIncludeHasHigherPriorityThanExclude() {
    apiStep.createAndStartRule(buildRule("CREATE,RENAME", "RENAME"));
    createAndAwaitSync(F1, F1_CONTENT);
    hdfsStep.rename(HADOOP_NAMENODE, path(F1), path(F1_RENAMED));
    waitUntilSynced(path(F1_RENAMED), F1_CONTENT);
    waitUntilDeletedOnTarget(path(F1));
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check include all types together")
  public void testSyncIncludeAllTypes() {
    apiStep.createAndStartRule(buildRule("CREATE,DELETE,RENAME,APPEND,METADATA", null));
    createAndAwaitSync(F1, F1_CONTENT);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(F1), APPENDED_PART);
    hdfsStep.rename(HADOOP_NAMENODE, path(F1), path(F1_RENAMED));
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(F1_RENAMED), CHANGED_PERMISSIONS);
    waitUntilSynced(path(F1_RENAMED), F1_APPENDED_CONTENT);
    waitUntilPermissionsSynced(path(F1_RENAMED), CHANGED_PERMISSIONS);
    waitUntilDeletedOnTarget(path(F1));
    createAndAwaitSync(F2, F2_CONTENT);
    hdfsStep.delete(HADOOP_NAMENODE, path(F2));
    waitUntilDeletedOnTarget(path(F2));
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check rule without include/exclude syncs all events")
  public void testSyncRuleWithoutFilters() {
    apiStep.createAndStartRule(buildRule(null, null));
    createAndAwaitSync(F1, F1_CONTENT);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(F1), APPENDED_PART);
    hdfsStep.rename(HADOOP_NAMENODE, path(F1), path(F1_RENAMED));
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(F1_RENAMED), CHANGED_PERMISSIONS);
    waitUntilSynced(path(F1_RENAMED), F1_APPENDED_CONTENT);
    waitUntilPermissionsSynced(path(F1_RENAMED), CHANGED_PERMISSIONS);
    waitUntilDeletedOnTarget(path(F1));
    createAndAwaitSync(F2, F2_CONTENT);
    hdfsStep.delete(HADOOP_NAMENODE, path(F2));
    waitUntilDeletedOnTarget(path(F2));
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check invalid/empty include/exclude params (negative)")
  public void testSyncInvalidParams() {
    assertRuleCreationFails(buildRule("", null));
    assertRuleCreationFails(buildRule(null, ""));
    assertRuleCreationFails(buildRule("", ""));
    assertRuleCreationFails(buildRule("UNKNOWN", null));
    assertRuleCreationFails(buildRule(null, "UNKNOWN"));
    assertRuleCreationFails(buildRule("MKDIR", null));
    assertRuleCreationFails(buildRule(null, "MKDIR"));
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check 2 parallel rules sync events to different destinations")
  public void testSyncTwoParallelRulesToDifferentDestinations() {
    apiStep.createAndStartRule(format(PARALLEL_SYNC_RULE_TEMPLATE, "test1", "test1"));
    apiStep.createAndStartRule(format(PARALLEL_SYNC_RULE_TEMPLATE, "test2", "test2"));
    hdfsStep.createFile(HADOOP_NAMENODE, SOURCE_DIR + "/test1/" + F1, F1_CONTENT);
    hdfsStep.createFile(HADOOP_NAMENODE, SOURCE_DIR + "/test2/" + F2, F2_CONTENT);
    waitUntilSynced(SOURCE_DIR + "/test1/" + F1, F1_CONTENT);
    waitUntilSynced(SOURCE_DIR + "/test2/" + F2, F2_CONTENT);
  }

  @Step("Build HDFS sync rule with include='{include}' and exclude='{exclude}'")
  private String buildRule(String include, String exclude) {
    String rule = SYNC_RULE_TEMPLATE;
    if (include != null) {
      rule += " -include " + include;
    }
    if (exclude != null) {
      rule += " -exclude " + exclude;
    }
    return rule;
  }

  @Step("Assert rule creation fails for rule: {rule}")
  private void assertRuleCreationFails(String rule) {
    apiStep.getRawClient().rules().addRule()
        .body(new SubmitRuleRequestDto().rule(rule))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .executeAs(Response::andReturn);
  }

  @Step("Create file '{fileName}' on source cluster and wait until it is synced to target cluster")
  private void createAndAwaitSync(String fileName, String content) {
    hdfsStep.createFile(HADOOP_NAMENODE, path(fileName), content);
    waitUntilSynced(path(fileName), content);
  }

  @Step("Create file '{fileName}' on both source and target clusters")
  private void seedFileOnBothClusters(String fileName, String content) {
    hdfsStep.createFile(HADOOP_NAMENODE, path(fileName), content);
    hdfsStep.createFile(TARGET_NAMENODE, path(fileName), content);
  }

  @Step("Wait until file '{filePath}' is synced to target cluster with content '{expectedContent}'")
  private void waitUntilSynced(String filePath, String expectedContent) {
    waitUntil(() -> hdfsStep.checkFileContent(TARGET_NAMENODE, filePath, expectedContent),
        EXTENDED_WAIT_PARAMS);
  }

  @Step("Wait until file '{filePath}' is deleted on target cluster")
  private void waitUntilDeletedOnTarget(String filePath) {
    waitUntil(() -> hdfsStep.checkFileNotExists(TARGET_NAMENODE, filePath), EXTENDED_WAIT_PARAMS);
  }

  @Step("Wait until file '{filePath}' has permissions '{expectedPermissions}' on target cluster")
  private void waitUntilPermissionsSynced(String filePath, String expectedPermissions) {
    waitUntil(() -> hdfsStep.checkPermissions(TARGET_NAMENODE, filePath, expectedPermissions),
        EXTENDED_WAIT_PARAMS);
  }

  @Step("Wait until actions count is {expectedCount}")
  private void waitUntilActionsCountIs(int expectedCount) {
    waitUntil(() -> assertThat(getActionNames()).hasSize(expectedCount), EXTENDED_WAIT_PARAMS);
  }

  @Step("Check no actions with names {actionNames} were created")
  private void checkNoActionWithName(String... actionNames) {
    assertThat(getActionNames())
        .as("Actions should not contain actions with names %s", Arrays.toString(actionNames))
        .doesNotContain(actionNames);
  }

  private List<String> getActionNames() {
    return sqlExecutor.queryFirstColumnAsStrings(ssmMetastoreDataSource, "SELECT action_name FROM action");
  }

  private static String path(String fileName) {
    return SOURCE_DIR + "/test/" + fileName;
  }
}
