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
package org.smartdata.test.suite.hdfs;

import io.qameta.allure.Feature;
import io.qameta.allure.Story;
import org.smartdata.client.generated.model.ActionStateDto;
import org.smartdata.test.annotation.RequiredComponents;
import org.smartdata.test.step.ApiStep;
import org.smartdata.test.step.HdfsStep;
import org.smartdata.test.suite.SsmBaseSuite;
import org.springframework.beans.factory.annotation.Autowired;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.nio.file.Path;

import static org.smartdata.test.model.SsmComponent.HADOOP_NAMENODE;
import static org.smartdata.test.model.SsmComponent.TARGET_NAMENODE;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.APPENDED_PART;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.CHANGED_PERMISSIONS;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.FILE_1;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.FILE_1_APPENDED_CONTENT;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.FILE_1_CONTENT;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.FILE_1_RENAMED;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.FILE_2;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.FILE_2_CONTENT;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.SOURCE_DIR;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.SYNC_DIR;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.SYNC_RULE;

@Feature("HDFS")
@RequiredComponents({HADOOP_NAMENODE, TARGET_NAMENODE})
public class HdfsSyncRuleTestSuite extends SsmBaseSuite {
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

  @Story("HDFS Sync rule")
  @Test(description = "Check default sync rule without any options syncs all event types")
  public void testSyncRuleWithoutFilters() {
    apiStep.createAndStartRule(SYNC_RULE);
    hdfsStep.createFileAndAwaitOn(HADOOP_NAMENODE, path(FILE_1), FILE_1_CONTENT, TARGET_NAMENODE);
    apiStep.checkActionsCountAndState(1, ActionStateDto.SUCCESSFUL);
    hdfsStep.appendToFile(HADOOP_NAMENODE, path(FILE_1), APPENDED_PART);
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1), FILE_1_APPENDED_CONTENT);
    apiStep.checkActionsCountAndState(2, ActionStateDto.SUCCESSFUL);
    hdfsStep.rename(HADOOP_NAMENODE, path(FILE_1), path(FILE_1_RENAMED));
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1_RENAMED), FILE_1_APPENDED_CONTENT);
    hdfsStep.waitUntilFileNotExists(TARGET_NAMENODE, path(FILE_1));
    apiStep.checkActionsCountAndState(3, ActionStateDto.SUCCESSFUL);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(FILE_1_RENAMED), CHANGED_PERMISSIONS);
    hdfsStep.waitUntilFileHasPermissions(TARGET_NAMENODE, path(FILE_1_RENAMED), CHANGED_PERMISSIONS);
    apiStep.checkActionsCountAndState(4, ActionStateDto.SUCCESSFUL);
    hdfsStep.delete(HADOOP_NAMENODE, path(FILE_1_RENAMED));
    hdfsStep.waitUntilFileNotExists(TARGET_NAMENODE, path(FILE_1_RENAMED));
    apiStep.checkActionsCountAndState(5, ActionStateDto.SUCCESSFUL);
  }

  @Story("HDFS Sync rule")
  @Test(description = "Check initial (base) sync copies files existing before rule start")
  public void testSyncPreExistingFiles() {
    hdfsStep.createFile(HADOOP_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.createFile(HADOOP_NAMENODE, path(FILE_2), FILE_2_CONTENT);
    apiStep.createAndStartRule(SYNC_RULE);
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_2), FILE_2_CONTENT);
  }

  @Story("HDFS Sync rule")
  @Test(description = "Check 2 parallel rules sync events from different sources")
  public void testSyncTwoParallelRulesToDifferentDestinations() {
    String rule1 = "file: path matches \"/data/test1/*\" | sync -dest hdfs://target-namenode.demo:8020/data/test/";
    String rule2 = "file: path matches \"/data/test2/*\" | sync -dest hdfs://target-namenode.demo:8020/data/test/";
    apiStep.createAndStartRule(rule1);
    apiStep.createAndStartRule(rule2);
    hdfsStep.createFile(HADOOP_NAMENODE, "/data/test1/file1", FILE_1_CONTENT);
    hdfsStep.createFile(HADOOP_NAMENODE, "/data/test2/file2", FILE_2_CONTENT);
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, "/data/test/file1", FILE_1_CONTENT);
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, "/data/test/file2", FILE_2_CONTENT);
  }

  private static String path(String relativePath) {
    return Path.of(SYNC_DIR, relativePath).toString();
  }
}
