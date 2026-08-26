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

import io.arenadata.test.model.UserRole;
import io.qameta.allure.Feature;
import io.qameta.allure.Step;
import io.qameta.allure.Story;
import io.restassured.response.Response;
import org.eclipse.jetty.http.HttpStatus;
import org.smartdata.client.generated.model.SubmitRuleRequestDto;
import org.smartdata.test.annotation.RequiredComponents;
import org.smartdata.test.service.SqlExecutor;
import org.smartdata.test.step.ActionsDetailsStep;
import org.smartdata.test.step.ActionsStep;
import org.smartdata.test.step.ApiStep;
import org.smartdata.test.step.DataBaseStep;
import org.smartdata.test.step.HmsStep;
import org.smartdata.test.step.LoginStep;
import org.smartdata.test.step.MenuStep;
import org.smartdata.test.step.TableStep;
import org.smartdata.test.suite.SsmWebBaseSuite;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.sql.DataSource;

import java.io.IOException;

import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.smartdata.test.model.SsmComponent.TARGET_NAMENODE;

@Feature("HMS")
@RequiredComponents(TARGET_NAMENODE)
public class HmsSyncRuleFilterEventsWebTestSuite extends SsmWebBaseSuite {
  @Autowired
  private LoginStep loginStep;
  @Autowired
  private MenuStep menuStep;
  @Autowired
  private DataBaseStep dataBaseStep;
  @Autowired
  private HmsStep hmsStep;
  @Autowired
  private ApiStep apiStep;
  @Autowired
  private TableStep tableStep;
  @Autowired
  private ActionsStep actionsStep;
  @Autowired
  private ActionsDetailsStep actionsDetailsStep;
  @Autowired
  private SqlExecutor sqlExecutor;
  @Autowired
  @Qualifier("hiveServer2DataSource")
  private DataSource hiveServer2DataSource;
  @Autowired
  @Qualifier("targetHiveServer2DataSource")
  private DataSource targetHiveServer2DataSource;

  private static final String HMS_SYNC_RULE_TEMPLATE =
      "hms : name matches \"%s.*\" | hms-sync -dest thrift://target-hive-metastore:9083/ -cascade -nameservice_rename \"source target\"";
  private static final String ALL_FILTERABLE_TYPES_SQL = String.join("\n",
      "CREATE DATABASE db1;",
      "ALTER DATABASE db1 SET DBPROPERTIES ('Date' = '2026-01-13');",
      "DROP DATABASE db1;");
  private static final String TEST_DATABASE_1 = "db1";

  @BeforeMethod
  public void restoreEnv() throws IOException {
    hmsStep.restoreEnv(true);
  }

  @BeforeMethod(dependsOnMethods = "restoreEnv")
  public void testPrepare() {
    loginStep.loginAs(UserRole.OWNER);
  }

  @Story("HMS Sync rule filtering events")
  @Test(description = "Check 'safe-copy' scenario: all events except DROP")
  public void testHmsSyncExcludeDrop() {
    createAndStartRuleWithIncludeExclude(null, "DROP");
    executeSqlAndCheckActionsCount(2);
    checkLastActionLog("Altering database db1",
        "Database was successfully altered");
    assertThat(dataBaseStep.getDatabases(targetHiveServer2DataSource)).contains(TEST_DATABASE_1);
  }

  @Story("HMS Sync rule filtering events")
  @Test(description = "Check all types separately: CREATE")
  public void testHmsSyncIncludeCreateOnly() {
    createAndStartRuleWithIncludeExclude("CREATE", null);
    executeSqlAndCheckActionsCount(1);
    checkLastActionLog("Creating database db1",
        "Database was successfully created");
  }

  @Story("HMS Sync rule filtering events")
  @Test(description = "Check all types separately: ALTER")
  public void testHmsSyncIncludeAlterOnly() {
    createAndStartRuleWithIncludeExclude("ALTER", null);
    executeSqlAndCheckActionsCount(1);
    checkLastActionLog("Altering database db1",
        "NoSuchObjectException(message:database hive.db1)");
  }

  @Story("HMS Sync rule filtering events")
  @Test(description = "Check all types separately: DROP")
  public void testHmsSyncIncludeDropOnly() {
    createAndStartRuleWithIncludeExclude("DROP", null);
    executeSqlAndCheckActionsCount(1);
    checkLastActionLog("Dropping database db1",
        "NoSuchObjectException(message:database hive.db1)");
  }

  @Story("HMS Sync rule filtering events")
  @Test(description = "Check multi-param -include CREATE,DROP")
  public void testHmsSyncIncludeCreateAndDrop() {
    createAndStartRuleWithIncludeExclude("CREATE,DROP", null);
    executeSqlAndCheckActionsCount(2);
    checkLastActionLog("Dropping database db1",
        "Database was successfully dropped");
  }

  @Story("HMS Sync rule filtering events")
  @Test(description = "Check duplicate param -include CREATE,CREATE")
  public void testHmsSyncIncludeDuplicateCreate() {
    createAndStartRuleWithIncludeExclude("CREATE,CREATE", null);
    executeSqlAndCheckActionsCount(1);
    checkLastActionLog("Creating database db1",
        "Database was successfully created");
  }

  @Story("HMS Sync rule filtering events")
  @Test(description = "Check params case insensitive -exclude DrOp,alter")
  public void testHmsSyncIncludeCaseInsensitive() {
    createAndStartRuleWithIncludeExclude(null, "DrOp,alter");
    executeSqlAndCheckActionsCount(1);
    checkLastActionLog("Creating database db1",
        "Database was successfully created");
  }

  @Story("HMS Sync rule filtering events")
  @Test(description = "Check include priority -include CREATE,ALTER -exclude ALTER")
  public void testHmsSyncIncludeHasHigherPriorityThanExclude() {
    createAndStartRuleWithIncludeExclude("CREATE,ALTER", "ALTER");
    executeSqlAndCheckActionsCount(2);
    checkLastActionLog("Altering database db1",
        "Database was successfully altered");
  }

  @Story("HMS Sync rule filtering events")
  @Test(description = "Check include all types together")
  public void testHmsSyncIncludeAllTypes() {
    createAndStartRuleWithIncludeExclude("CREATE,DROP,ALTER", null);
    executeSqlAndCheckActionsCount(3);
    checkLastActionLog("Dropping database db1",
        "Database was successfully dropped");
  }

  @Story("HMS Sync rule filtering events")
  @Test(description = "Check invalid/empty include/exclude params (negative)")
  public void testHmsSyncInvalidParams() {
    assertRuleCreationFails(buildRule("", null));
    assertRuleCreationFails(buildRule(null, ""));
    assertRuleCreationFails(buildRule("", ""));
    assertRuleCreationFails(buildRule("UNKNOWN", null));
    assertRuleCreationFails(buildRule(null, "RENAME"));
  }

  @Step("Create and start HMS sync rule with include='{include}' and exclude='{exclude}'")
  private void createAndStartRuleWithIncludeExclude(String include, String exclude) {
    apiStep.createAndStartRule(buildRule(include, exclude));
  }

  @Step("Execute SQL and check actions count = {expectedCount}")
  private void executeSqlAndCheckActionsCount(int expectedCount) {
    sqlExecutor.executeSql(hiveServer2DataSource, ALL_FILTERABLE_TYPES_SQL);
    menuStep.openActionsPage();
    tableStep.setRefreshingFrequency(1);
    tableStep.checkTableRowsCountIs(expectedCount);
  }

  @Step("Build HMS sync rule with include='{include}' and exclude='{exclude}'")
  private String buildRule(String include, String exclude) {
    String rule = format(HMS_SYNC_RULE_TEMPLATE, TEST_DATABASE_1);
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

  @Step("Check last action log contains {expectedLogTexts}")
  private void checkLastActionLog(String... expectedLogTexts) {
    actionsStep.openFirstActionDetails();
    actionsDetailsStep.openActionDetailsLog()
        .checkActionDetailsLogContainsTexts(expectedLogTexts);
  }
}