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
package org.smartdata.test.suite.hdfs;

import io.qameta.allure.Feature;
import io.qameta.allure.Step;
import io.qameta.allure.Story;
import org.smartdata.client.generated.model.ActionStateDto;
import org.smartdata.test.annotation.RequiredComponents;
import org.smartdata.test.step.ApiStep;
import org.smartdata.test.step.HdfsStep;
import org.smartdata.test.suite.SsmBaseSuite;
import org.springframework.beans.factory.annotation.Autowired;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.nio.file.Path;

import static org.smartdata.test.model.SsmComponent.HADOOP_NAMENODE;
import static org.smartdata.test.model.SsmComponent.TARGET_NAMENODE;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.APPENDED_PART;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.APPENDED_PART_2;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.CHANGED_PERMISSIONS;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.DEFAULT_PERMISSIONS;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.FILE_1;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.FILE_1_APPENDED_CONTENT;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.FILE_1_CONTENT;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.FILE_1_RENAMED;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.FILE_2;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.FILE_2_APPENDED_CONTENT;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.FILE_2_CONTENT;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.FILE_2_RENAMED;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.SOURCE_DIR;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.SYNC_DIR;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.SYNC_RULE;

@Feature("HDFS")
@RequiredComponents({HADOOP_NAMENODE, TARGET_NAMENODE})
public class HdfsSyncRuleFilterEventsTestSuite extends SsmBaseSuite {
  @Autowired
  private HdfsStep hdfsStep;
  @Autowired
  private ApiStep apiStep;

  @BeforeMethod
  public void cleanHdfs() {
    apiStep.deleteAllRules();
    hdfsStep.delete(HADOOP_NAMENODE, SOURCE_DIR);
    hdfsStep.delete(TARGET_NAMENODE, SOURCE_DIR);
    hdfsStep.createDirectory(HADOOP_NAMENODE, SOURCE_DIR);
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check 'safe-copy' scenario: all events except DELETE")
  public void testSyncExcludeDelete() {
    apiStep.createAndStartRule(buildRule(null, "DELETE"));
    hdfsStep.createFileAndAwaitOn(HADOOP_NAMENODE, path(FILE_1), FILE_1_CONTENT, TARGET_NAMENODE);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(FILE_1), APPENDED_PART);
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1), FILE_1_APPENDED_CONTENT);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(FILE_1), CHANGED_PERMISSIONS);
    hdfsStep.waitUntilFileHasPermissions(TARGET_NAMENODE, path(FILE_1), CHANGED_PERMISSIONS);
    hdfsStep.rename(HADOOP_NAMENODE, path(FILE_1), path(FILE_1_RENAMED));
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1_RENAMED), FILE_1_APPENDED_CONTENT);
    hdfsStep.waitUntilFileNotExists(TARGET_NAMENODE, path(FILE_1));
    hdfsStep.delete(HADOOP_NAMENODE, path(FILE_1_RENAMED));
    hdfsStep.checkFileContent(TARGET_NAMENODE, path(FILE_1_RENAMED), FILE_1_APPENDED_CONTENT);
    hdfsStep.checkPermissions(TARGET_NAMENODE, path(FILE_1_RENAMED), CHANGED_PERMISSIONS);
    hdfsStep.checkFileNotExists(TARGET_NAMENODE, path(FILE_1));
    apiStep.checkActionsCountAndState(4, ActionStateDto.SUCCESSFUL);
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check all types separately: CREATE")
  public void testSyncIncludeCreateOnly() {
    apiStep.createAndStartRule(buildRule("CREATE", null));
    hdfsStep.createFileAndAwaitOn(HADOOP_NAMENODE, path(FILE_1), FILE_1_CONTENT, TARGET_NAMENODE);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(FILE_1), APPENDED_PART);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(FILE_1), CHANGED_PERMISSIONS);
    hdfsStep.rename(HADOOP_NAMENODE, path(FILE_1), path(FILE_1_RENAMED));
    hdfsStep.delete(HADOOP_NAMENODE, path(FILE_1_RENAMED));
    hdfsStep.checkFileContent(TARGET_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.checkPermissions(TARGET_NAMENODE, path(FILE_1), DEFAULT_PERMISSIONS);
    hdfsStep.checkFileNotExists(TARGET_NAMENODE, path(FILE_1_RENAMED));
    apiStep.checkActionsCountAndState(1, ActionStateDto.SUCCESSFUL);
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check all types separately: DELETE")
  public void testSyncIncludeDeleteOnly() {
    apiStep.createAndStartRule(buildRule("DELETE", null));
    hdfsStep.createFileOnBothClusters(HADOOP_NAMENODE, TARGET_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.delete(HADOOP_NAMENODE, path(FILE_1));
    hdfsStep.waitUntilFileNotExists(TARGET_NAMENODE, path(FILE_1));
    hdfsStep.createFile(HADOOP_NAMENODE, path(FILE_2), FILE_2_CONTENT);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(FILE_2), APPENDED_PART_2);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(FILE_2), CHANGED_PERMISSIONS);
    hdfsStep.rename(HADOOP_NAMENODE, path(FILE_2), path(FILE_2_RENAMED));
    hdfsStep.checkFileNotExists(TARGET_NAMENODE, path(FILE_2));
    hdfsStep.checkFileNotExists(TARGET_NAMENODE, path(FILE_2_RENAMED));
    apiStep.checkActionsCountAndState(1, ActionStateDto.SUCCESSFUL);
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check all types separately: RENAME")
  public void testSyncIncludeRenameOnly() {
    apiStep.createAndStartRule(buildRule("RENAME", null));
    hdfsStep.createFileOnBothClusters(HADOOP_NAMENODE, TARGET_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.rename(HADOOP_NAMENODE, path(FILE_1), path(FILE_1_RENAMED));
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1_RENAMED), FILE_1_CONTENT);
    hdfsStep.waitUntilFileNotExists(TARGET_NAMENODE, path(FILE_1));
    hdfsStep.createFile(HADOOP_NAMENODE, path(FILE_2), FILE_2_CONTENT);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(FILE_2), APPENDED_PART_2);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(FILE_2), CHANGED_PERMISSIONS);
    hdfsStep.delete(HADOOP_NAMENODE, path(FILE_2));
    hdfsStep.checkFileNotExists(TARGET_NAMENODE, path(FILE_2));
    hdfsStep.checkFileNotExists(TARGET_NAMENODE, path(FILE_2_RENAMED));
    apiStep.checkActionsCountAndState(1, ActionStateDto.SUCCESSFUL);
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check all types separately: APPEND")
  public void testSyncIncludeAppendOnly() {
    apiStep.createAndStartRule(buildRule("APPEND", null));
    hdfsStep.createFile(HADOOP_NAMENODE, path(FILE_1), "");
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(FILE_1), APPENDED_PART);
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1), APPENDED_PART);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(FILE_1), CHANGED_PERMISSIONS);
    hdfsStep.rename(HADOOP_NAMENODE, path(FILE_1), path(FILE_1_RENAMED));
    hdfsStep.delete(HADOOP_NAMENODE, path(FILE_1_RENAMED));
    apiStep.checkActionsCountAndState(1, ActionStateDto.SUCCESSFUL);
    hdfsStep.createFile(HADOOP_NAMENODE, path(FILE_2), FILE_2_CONTENT);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(FILE_2), APPENDED_PART_2);
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_2), FILE_2_APPENDED_CONTENT);
    apiStep.checkActionsCountAndState(3, ActionStateDto.SUCCESSFUL);
    hdfsStep.checkFileContent(TARGET_NAMENODE, path(FILE_1), APPENDED_PART);
    hdfsStep.checkPermissions(TARGET_NAMENODE, path(FILE_1), DEFAULT_PERMISSIONS);
    hdfsStep.checkFileNotExists(TARGET_NAMENODE, path(FILE_1_RENAMED));
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check all types separately: METADATA")
  public void testSyncIncludeMetadataOnly() {
    apiStep.createAndStartRule(buildRule("METADATA", null));
    hdfsStep.createFileOnBothClusters(HADOOP_NAMENODE, TARGET_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(FILE_1), CHANGED_PERMISSIONS);
    hdfsStep.waitUntilFileHasPermissions(TARGET_NAMENODE, path(FILE_1), CHANGED_PERMISSIONS);
    apiStep.checkActionsCountAndState(1, ActionStateDto.SUCCESSFUL);
    hdfsStep.createFile(HADOOP_NAMENODE, path(FILE_2), FILE_2_CONTENT);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(FILE_2), APPENDED_PART_2);
    hdfsStep.rename(HADOOP_NAMENODE, path(FILE_2), path(FILE_2_RENAMED));
    hdfsStep.delete(HADOOP_NAMENODE, path(FILE_2_RENAMED));
    hdfsStep.checkFileNotExists(TARGET_NAMENODE, path(FILE_2));
    hdfsStep.checkFileNotExists(TARGET_NAMENODE, path(FILE_2_RENAMED));
    apiStep.checkActionsCountAndState(1, ActionStateDto.SUCCESSFUL);
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check multi-param -include CREATE,DELETE")
  public void testSyncIncludeCreateAndDelete() {
    apiStep.createAndStartRule(buildRule("CREATE,DELETE", null));
    hdfsStep.createFileAndAwaitOn(HADOOP_NAMENODE, path(FILE_1), FILE_1_CONTENT, TARGET_NAMENODE);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(FILE_1), APPENDED_PART);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(FILE_1), CHANGED_PERMISSIONS);
    hdfsStep.rename(HADOOP_NAMENODE, path(FILE_1), path(FILE_1_RENAMED));
    hdfsStep.createFileAndAwaitOn(HADOOP_NAMENODE, path(FILE_2), FILE_2_CONTENT, TARGET_NAMENODE);
    apiStep.checkActionsCountAndState(2, ActionStateDto.SUCCESSFUL);
    hdfsStep.checkFileContent(TARGET_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.checkPermissions(TARGET_NAMENODE, path(FILE_1), DEFAULT_PERMISSIONS);
    hdfsStep.checkFileNotExists(TARGET_NAMENODE, path(FILE_1_RENAMED));
    hdfsStep.delete(HADOOP_NAMENODE, path(FILE_2));
    hdfsStep.waitUntilFileNotExists(TARGET_NAMENODE, path(FILE_2));
    apiStep.checkActionsCountAndState(3, ActionStateDto.SUCCESSFUL);
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check duplicate param -include CREATE,CREATE")
  public void testSyncIncludeDuplicateCreate() {
    apiStep.createAndStartRule(buildRule("CREATE,CREATE", null));
    hdfsStep.createFileAndAwaitOn(HADOOP_NAMENODE, path(FILE_1), FILE_1_CONTENT, TARGET_NAMENODE);
    hdfsStep.checkFileContent(TARGET_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    apiStep.checkActionsCountAndState(1, ActionStateDto.SUCCESSFUL);
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check include priority + case insensitive: -include Create,rename -exclude reNAme")
  public void testSyncIncludeHasHigherPriorityThanExclude() {
    apiStep.createAndStartRule(buildRule("Create,rename", "reNAme"));
    hdfsStep.createFileAndAwaitOn(HADOOP_NAMENODE, path(FILE_1), FILE_1_CONTENT, TARGET_NAMENODE);
    hdfsStep.rename(HADOOP_NAMENODE, path(FILE_1), path(FILE_1_RENAMED));
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1_RENAMED), FILE_1_CONTENT);
    hdfsStep.waitUntilFileNotExists(TARGET_NAMENODE, path(FILE_1));
    apiStep.checkActionsCountAndState(2, ActionStateDto.SUCCESSFUL);
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check include all types together")
  public void testSyncIncludeAllTypes() {
    apiStep.createAndStartRule(buildRule("CREATE,DELETE,RENAME,APPEND,METADATA", null));
    hdfsStep.createFileAndAwaitOn(HADOOP_NAMENODE, path(FILE_1), FILE_1_CONTENT, TARGET_NAMENODE);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(FILE_1), APPENDED_PART);
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1), FILE_1_APPENDED_CONTENT);
    hdfsStep.rename(HADOOP_NAMENODE, path(FILE_1), path(FILE_1_RENAMED));
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1_RENAMED), FILE_1_APPENDED_CONTENT);
    hdfsStep.waitUntilFileNotExists(TARGET_NAMENODE, path(FILE_1));
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(FILE_1_RENAMED), CHANGED_PERMISSIONS);
    hdfsStep.waitUntilFileHasPermissions(TARGET_NAMENODE, path(FILE_1_RENAMED), CHANGED_PERMISSIONS);
    hdfsStep.delete(HADOOP_NAMENODE, path(FILE_1_RENAMED));
    hdfsStep.waitUntilFileNotExists(TARGET_NAMENODE, path(FILE_1_RENAMED));
    apiStep.checkActionsCountAndState(5, ActionStateDto.SUCCESSFUL);
  }

  @Story("HDFS Sync rule filtering events")
  @Test(description = "Check invalid/empty include/exclude params (negative)",
      dataProvider = "invalidIncludeExclude")
  public void testSyncInvalidParams(String include, String exclude) {
    apiStep.checkRuleCreationIsRejected(buildRule(include, exclude));
  }

  @DataProvider(name = "invalidIncludeExclude")
  public Object[][] invalidIncludeExclude() {
    return new Object[][]{
        {"", null},
        {null, ""},
        {"UNKNOWN", null},
        {null, "UNKNOWN"},
        {"MKDIR", null},
        {null, "MKDIR"},
        {"CREATE,UNKNOWN", null},
        {null, "CREATE,UNKNOWN"}
    };
  }

  @Step("Build HDFS sync rule with include='{include}' and exclude='{exclude}'")
  private String buildRule(String include, String exclude) {
    String rule = SYNC_RULE;
    if (include != null) {
      rule += " -include " + include;
    }
    if (exclude != null) {
      rule += " -exclude " + exclude;
    }
    return rule;
  }

  private static String path(String fileName) {
    return Path.of(SYNC_DIR, fileName).toString();
  }
}