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
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.CHANGED_PERMISSIONS;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.DEFAULT_PERMISSIONS;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.FILE_1;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.FILE_1_CONTENT;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.SOURCE_DIR;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.SYNC_DIR;
import static org.smartdata.test.util.constant.HdfsSyncRuleConstants.SYNC_RULE;

@Feature("HDFS")
@RequiredComponents({HADOOP_NAMENODE, TARGET_NAMENODE})
public class HdfsSyncRulePreserveTestSuite extends SsmBaseSuite {
  @Autowired
  private HdfsStep hdfsStep;
  @Autowired
  private ApiStep apiStep;

  private static final String NEW_OWNER = "newOwner";
  private static final String NEW_GROUP = "newGroup";
  private static final int CHANGED_REPLICATION = 2;
  private static final long MODIFICATION_TIME_OFFSET_MS = 60_000;

  @BeforeMethod
  public void cleanHdfs() {
    apiStep.deleteAllRules();
    hdfsStep.delete(HADOOP_NAMENODE, SOURCE_DIR);
    hdfsStep.delete(TARGET_NAMENODE, SOURCE_DIR);
    hdfsStep.createDirectory(HADOOP_NAMENODE, SOURCE_DIR);
  }

  @Story("HDFS Sync rule preserve")
  @Test(description = "Check default sync without -preserve transfers owner, group and permissions only")
  public void testSyncPreserveDefaultAttributes() {
    long staleModificationTime = staleModificationTime();
    hdfsStep.createFile(HADOOP_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    String defaultReplication = hdfsStep.getReplication(HADOOP_NAMENODE, path(FILE_1));
    hdfsStep.setOwner(HADOOP_NAMENODE, path(FILE_1), NEW_OWNER, NEW_GROUP);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(FILE_1), CHANGED_PERMISSIONS);
    hdfsStep.setReplication(HADOOP_NAMENODE, path(FILE_1), CHANGED_REPLICATION);
    hdfsStep.setModificationTime(HADOOP_NAMENODE, path(FILE_1), staleModificationTime);
    apiStep.createAndStartRule(buildRule(null));
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.waitUntilFileHasOwnerAndGroup(TARGET_NAMENODE, path(FILE_1), NEW_OWNER, NEW_GROUP);
    hdfsStep.waitUntilFileHasPermissions(TARGET_NAMENODE, path(FILE_1), CHANGED_PERMISSIONS);
    hdfsStep.checkReplication(TARGET_NAMENODE, path(FILE_1), defaultReplication);
    hdfsStep.waitUntilFileModificationTimeAfter(TARGET_NAMENODE, path(FILE_1), staleModificationTime);
  }

  @Story("HDFS Sync rule preserve")
  @Test(description = "Check -preserve owner transfers only owner to target cluster")
  public void testSyncPreserveOwner() {
    hdfsStep.createFile(HADOOP_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    String defaultGroup = hdfsStep.getGroup(HADOOP_NAMENODE, path(FILE_1));
    hdfsStep.setOwner(HADOOP_NAMENODE, path(FILE_1), NEW_OWNER, NEW_GROUP);
    apiStep.createAndStartRule(buildRule("owner"));
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.waitUntilFileHasOwnerAndGroup(TARGET_NAMENODE, path(FILE_1), NEW_OWNER, NEW_GROUP);
  }

  @Story("HDFS Sync rule preserve")
  @Test(description = "Check -preserve group transfers only group to target cluster")
  public void testSyncPreserveGroup() {
    hdfsStep.createFile(HADOOP_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    String defaultOwner = hdfsStep.getOwner(HADOOP_NAMENODE, path(FILE_1));
    hdfsStep.setOwner(HADOOP_NAMENODE, path(FILE_1), NEW_OWNER, NEW_GROUP);
    apiStep.createAndStartRule(buildRule("group"));
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.waitUntilFileHasOwnerAndGroup(TARGET_NAMENODE, path(FILE_1), defaultOwner, NEW_GROUP);
  }

  @Story("HDFS Sync rule preserve")
  @Test(description = "Check -preserve permissions transfers only permissions to target cluster")
  public void testSyncPreservePermissions() {
    hdfsStep.createFile(HADOOP_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    String defaultOwner = hdfsStep.getOwner(HADOOP_NAMENODE, path(FILE_1));
    String defaultGroup = hdfsStep.getGroup(HADOOP_NAMENODE, path(FILE_1));
    hdfsStep.setOwner(HADOOP_NAMENODE, path(FILE_1), NEW_OWNER, NEW_GROUP);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(FILE_1), CHANGED_PERMISSIONS);
    apiStep.createAndStartRule(buildRule("permissions"));
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.waitUntilFileHasPermissions(TARGET_NAMENODE, path(FILE_1), CHANGED_PERMISSIONS);
    hdfsStep.checkOwner(TARGET_NAMENODE, path(FILE_1), defaultOwner, defaultGroup);
  }

  @Story("HDFS Sync rule preserve")
  @Test(description = "Check -preserve replication transfers only replication factor to target cluster")
  public void testSyncPreserveReplication() {
    hdfsStep.createFile(HADOOP_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.setOwner(HADOOP_NAMENODE, path(FILE_1), NEW_OWNER, NEW_GROUP);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(FILE_1), CHANGED_PERMISSIONS);
    hdfsStep.setReplication(HADOOP_NAMENODE, path(FILE_1), CHANGED_REPLICATION);
    apiStep.createAndStartRule(buildRule("replication"));
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.waitUntilFileHasReplication(TARGET_NAMENODE, path(FILE_1), CHANGED_REPLICATION);
    hdfsStep.checkPermissions(TARGET_NAMENODE, path(FILE_1), DEFAULT_PERMISSIONS);
  }

  @Story("HDFS Sync rule preserve")
  @Test(description = "Check -preserve modification-time transfers only modification time to target cluster")
  public void testSyncPreserveModificationTime() {
    long staleModificationTime = staleModificationTime();
    hdfsStep.createFile(HADOOP_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(FILE_1), CHANGED_PERMISSIONS);
    hdfsStep.setModificationTime(HADOOP_NAMENODE, path(FILE_1), staleModificationTime);
    apiStep.createAndStartRule(buildRule("modification-time"));
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.waitUntilFileHasModificationTime(TARGET_NAMENODE, path(FILE_1), staleModificationTime);
    hdfsStep.checkPermissions(TARGET_NAMENODE, path(FILE_1), DEFAULT_PERMISSIONS);
  }

  @Story("HDFS Sync rule preserve")
  @Test(description = "Check multi-param + case insensitive -preserve OWNER,Group transfers owner and group only")
  public void testSyncPreserveOwnerGroup() {
    hdfsStep.createFile(HADOOP_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.setOwner(HADOOP_NAMENODE, path(FILE_1), NEW_OWNER, NEW_GROUP);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(FILE_1), CHANGED_PERMISSIONS);
    apiStep.createAndStartRule(buildRule("OWNER,Group"));
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.waitUntilFileHasOwnerAndGroup(TARGET_NAMENODE, path(FILE_1), NEW_OWNER, NEW_GROUP);
    hdfsStep.checkPermissions(TARGET_NAMENODE, path(FILE_1), DEFAULT_PERMISSIONS);
  }

  @Story("HDFS Sync rule preserve")
  @Test(description = "Check duplicate param -preserve owner,owner transfers only owner")
  public void testSyncPreserveDuplicateOwner() {
    hdfsStep.createFile(HADOOP_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    String defaultGroup = hdfsStep.getGroup(HADOOP_NAMENODE, path(FILE_1));
    hdfsStep.setOwner(HADOOP_NAMENODE, path(FILE_1), NEW_OWNER, NEW_GROUP);
    apiStep.createAndStartRule(buildRule("owner,owner"));
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.waitUntilFileHasOwnerAndGroup(TARGET_NAMENODE, path(FILE_1), NEW_OWNER, defaultGroup);
  }

  @Story("HDFS Sync rule preserve")
  @Test(description = "Check all preserve attributes together: owner,group,permissions,replication,modification-time")
  public void testSyncPreserveAllAttributes() {
    long staleModificationTime = staleModificationTime();
    hdfsStep.createFile(HADOOP_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.setOwner(HADOOP_NAMENODE, path(FILE_1), NEW_OWNER, NEW_GROUP);
    hdfsStep.setPermissions(HADOOP_NAMENODE, path(FILE_1), CHANGED_PERMISSIONS);
    hdfsStep.setReplication(HADOOP_NAMENODE, path(FILE_1), CHANGED_REPLICATION);
    hdfsStep.setModificationTime(HADOOP_NAMENODE, path(FILE_1), staleModificationTime);
    apiStep.createAndStartRule(buildRule("owner,group,permissions,replication,modification-time"));
    hdfsStep.waitUntilFileHasContent(TARGET_NAMENODE, path(FILE_1), FILE_1_CONTENT);
    hdfsStep.waitUntilFileHasOwnerAndGroup(TARGET_NAMENODE, path(FILE_1), NEW_OWNER, NEW_GROUP);
    hdfsStep.waitUntilFileHasPermissions(TARGET_NAMENODE, path(FILE_1), CHANGED_PERMISSIONS);
    hdfsStep.waitUntilFileHasReplication(TARGET_NAMENODE, path(FILE_1), CHANGED_REPLICATION);
    hdfsStep.waitUntilFileHasModificationTime(TARGET_NAMENODE, path(FILE_1), staleModificationTime);
  }

  @Story("HDFS Sync rule preserve")
  @Test(description = "Check invalid -preserve params (negative)",
      dataProvider = "invalidPreserveValues")
  public void testSyncInvalidPreserveValue(String preserve) {
    apiStep.checkRuleCreationIsRejected(buildRule(preserve));
  }

  @DataProvider(name = "invalidPreserveValues")
  public Object[][] invalidPreserveValues() {
    return new Object[][]{
        {""},
        {"UNKNOWN"},
        {"owner,UNKNOWN"}
    };
  }

  private static long staleModificationTime() {
    return System.currentTimeMillis() - MODIFICATION_TIME_OFFSET_MS;
  }

  @Step("Build HDFS sync rule with preserve='{preserve}'")
  private String buildRule(String preserve) {
    String rule = SYNC_RULE;
    if (preserve != null) {
      rule += " -preserve " + preserve;
    }
    return rule;
  }

  private static String path(String fileName) {
    return Path.of(SYNC_DIR, fileName).toString();
  }
}
