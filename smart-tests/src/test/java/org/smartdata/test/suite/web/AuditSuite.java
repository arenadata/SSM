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
package org.smartdata.test.suite.web;

import io.arenadata.test.model.UserRole;
import io.qameta.allure.Feature;
import io.qameta.allure.Step;
import io.qameta.allure.Story;
import io.qameta.allure.TmsLink;
import io.restassured.response.Response;
import org.smartdata.client.generated.model.SubmitActionRequestDto;
import org.smartdata.test.service.FrequencyTestScheduledService;
import org.smartdata.test.step.ApiStep;
import org.smartdata.test.step.AuditStep;
import org.smartdata.test.step.DataBaseStep;
import org.smartdata.test.step.LoginStep;
import org.smartdata.test.step.MenuStep;
import org.smartdata.test.step.TableStep;
import org.smartdata.test.suite.SsmWebBaseSuite;
import org.smartdata.test.util.comparator.UiDateTimeComparator;
import org.springframework.beans.factory.annotation.Autowired;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.smartdata.test.element.AuditPageElement.AuditTableColumn.DATE;
import static org.smartdata.test.element.AuditPageElement.AuditTableColumn.ID;
import static org.smartdata.test.element.AuditPageElement.AuditTableColumn.OBJECT_ID;
import static org.smartdata.test.element.AuditPageElement.AuditTableColumn.OBJECT_TYPE;
import static org.smartdata.test.element.AuditPageElement.AuditTableColumn.OPERATION;
import static org.smartdata.test.element.AuditPageElement.AuditTableColumn.USER;
import static org.smartdata.test.model.SortOrder.ASC;
import static org.smartdata.test.model.SortOrder.DESC;

@Feature("Audit page")
public class AuditSuite extends SsmWebBaseSuite {

  @Autowired
  private LoginStep loginStep;

  @Autowired
  private MenuStep menuStep;

  @Autowired
  private TableStep tableStep;

  @Autowired
  private DataBaseStep dataBaseStep;

  @Autowired
  private AuditStep auditStep;

  @Autowired
  private ApiStep apiStep;

  @BeforeMethod
  public void testPrepare() {
    loginStep.loginAs(UserRole.OWNER);
    menuStep.openAuditPage();
  }

  @TmsLink("90594")
  @Story("Audit")
  @Test(description = "Check sorting")
  public void testSorting() {
    prepareDataForSortingTest();
    tableStep.checkDefaultSorting(ID)
        .checkSorting(USER)
        .checkSorting(DATE, new UiDateTimeComparator())
        .checkSorting(OBJECT_TYPE)
        .checkSorting(OBJECT_ID)
        .checkSorting(OPERATION);
  }

  @TmsLink("90593")
  @Story("Audit")
  @Test(description = "Check filtration")
  public void testFiltration() {
    prepareDataForFiltrationTest();
    auditStep.checkAuditUserFiltration()
        .checkAuditDateFiltration()
        .checkAuditObjectTypeFiltration()
        .checkAuditOperationFiltration()
        .checkAuditResultFiltration();
  }

  @TmsLink("91398")
  @Story("Audit")
  @Test(description = "Check frequency")
  public void testFrequency() {
    FrequencyTestScheduledService frequencyTestScheduledService = new FrequencyTestScheduledService();
    try {
      String ruleText = "file: path matches \"/tmp/test/*\" | read";
      frequencyTestScheduledService.run(() -> apiStep.createRule(ruleText));
      tableStep.clickOnSortingColumn(DATE)
          .checkSelectedSorting(DATE, ASC)
          .clickOnSortingColumn(DATE)
          .checkSelectedSorting(DATE, DESC);
      tableStep.checkRefreshingFrequency(DATE);
    } finally {
      frequencyTestScheduledService.shutdownAndAwaitTermination();
    }
  }

  @Step("Create audit events for sorting test")
  private void prepareDataForSortingTest() {
    dataBaseStep.insertDataForAuditSortTest();
    tableStep.refreshPage();
    tableStep.checkTableRowsCountIs(4);
  }

  @Step("Create audit events for filtration test")
  private void prepareDataForFiltrationTest() {
    apiStep.getRawClient().actions().submitAction()
        .body(new SubmitActionRequestDto().action("NONEXISTENT"))
        .respSpec(response -> response.expectStatusCode(400))
        .executeAs(Response::andReturn);
    dataBaseStep.insertDataForAuditFilterTest();
    tableStep.refreshPage();
    tableStep.checkTableRowsCountIs(2);
  }
}
