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
package org.smartdata.test.suite;

import io.arenadata.test.model.UserRole;
import io.qameta.allure.Feature;
import io.qameta.allure.Step;
import io.qameta.allure.Story;
import io.qameta.allure.TmsLink;
import org.smartdata.test.step.ActionsDetailsStep;
import org.smartdata.test.step.ActionsStep;
import org.smartdata.test.step.ApiStep;
import org.smartdata.test.step.DataBaseStep;
import org.smartdata.test.step.LoginStep;
import org.smartdata.test.step.MenuStep;
import org.smartdata.test.step.TableStep;
import org.smartdata.test.util.comparator.ActionStatusComparator;
import org.smartdata.test.util.comparator.DashIsMaxComparator;
import org.springframework.beans.factory.annotation.Autowired;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.smartdata.test.element.ActionsDetailsPageElement.HEADER_SUCCESSFUL_ICON;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.ACTION;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.CREATE_TIME;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.FINISH_TIME;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.HOST;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.ID;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.STATUS;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.TYPE;
import static org.smartdata.test.model.ActionStatus.SUCCESSFUL;
import static org.smartdata.test.model.SortOrder.ASC;
import static org.smartdata.test.model.SortOrder.DESC;

@Feature("Actions page")
public class ActionsSuite extends SsmBaseSuite {
  private static final String TEST_ACTION_TEXT = "sleep -ms 100";

  @Autowired
  private LoginStep loginStep;

  @Autowired
  private MenuStep menuStep;

  @Autowired
  private TableStep tableStep;

  @Autowired
  private ActionsStep actionsStep;

  @Autowired
  private DataBaseStep dataBaseStep;

  @Autowired
  private ApiStep apiStep;

  @Autowired
  private ActionsDetailsStep actionsDetailsStep;

  @BeforeMethod
  public void testPrepare() {
    loginStep.loginAs(UserRole.OWNER);
    menuStep.openActionsPage();
  }

  @TmsLink("90590")
  @Story("Actions")
  @Test(description = "Check `Submit action` button")
  public void testSubmitAction() {
    tableStep.checkTableIsEmpty();
    actionsStep.checkSubmitDialogCancelButton(TEST_ACTION_TEXT)
        .refreshPage();
    tableStep.checkTableIsEmpty();
    actionsStep.checkSubmitDialogRunButton(TEST_ACTION_TEXT);
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(ACTION, TEST_ACTION_TEXT)
        .checkColumnValueInFirstRow(STATUS, SUCCESSFUL.getText());
  }

  @TmsLink("90538")
  @Story("Actions")
  @Test(description = "Check sorting")
  public void testSorting() {
    prepareDataForSortingTest();
    tableStep.checkDefaultSorting(ID)
        .checkSorting(HOST, new DashIsMaxComparator())
        .checkSorting(CREATE_TIME)
        .checkSorting(FINISH_TIME, new DashIsMaxComparator())
        .checkSorting(STATUS, new ActionStatusComparator())
        .checkSorting(TYPE);
  }

  @TmsLink("90210")
  @Story("Actions")
  @Test(description = "Check filtration")
  public void testFiltration() {
    prepareDataForFilterTest();
    actionsStep.checkActionTextFiltration()
        .checkHostFiltration()
        .checkCreateTimeFiltration()
        .checkFinishTimeFiltration()
        .checkStatusFiltration()
        .checkTypeFiltration();
  }

  @TmsLink("90540")
  @Story("Actions")
  @Test(description = "Check 'Repeat action' button")
  public void testRepeatActionButton() {
    apiStep.createAction(TEST_ACTION_TEXT);
    actionsStep.refreshPage();
    tableStep.checkTableRowsCountIs(1);
    actionsStep.checkRepeatActionButton();
  }

  @TmsLink("90251")
  @Story("Actions")
  @Test(description = "Check action details page")
  public void testActionDetailsPage() {
    prepareDataForActionDetailsPageTest();
    actionsStep.openFirstActionDetails();
    tableStep.checkTableRowsCountIs(1);
    actionsDetailsStep.checkFakeActionDetailsTableRow()
        .checkActionDetailsHeaderInfo("sleep", "-ms 10", HEADER_SUCCESSFUL_ICON)
        .checkActionDetailsLogViewValues("FAKE RESULT", "FAKE LOG");
  }

  @TmsLink("90251")
  @Story("Actions")
  @Test(description = "Check action details 'Repeat action' button")
  public void testActionDetailsRepeatActionButton() {
    apiStep.createAction(TEST_ACTION_TEXT);
    actionsStep.refreshPage();
    tableStep.checkTableRowsCountIs(1);
    actionsStep.openFirstActionDetails();
    actionsDetailsStep.repeatAction();
    menuStep.openActionsPage();
    tableStep.checkTableRowsCountIs(2);
  }

  @TmsLink("90537")
  @Story("Actions")
  @Test(description = "Check frequency")
  public void testFrequency() {
    ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    ScheduledFuture<?> scheduledFuture =
        scheduler.scheduleAtFixedRate(() -> apiStep.createAction(TEST_ACTION_TEXT), 0, 1, SECONDS);
    tableStep.clickOnSortingColumn(CREATE_TIME)
        .checkSelectedSorting(CREATE_TIME, ASC)
        .clickOnSortingColumn(CREATE_TIME)
        .checkSelectedSorting(CREATE_TIME, DESC);
    tableStep.checkRefreshingFrequency(CREATE_TIME);
    scheduledFuture.cancel(true);
    scheduler.shutdown();
  }

  @TmsLink("85966")
  @Story("Actions")
  @Test(description = "Check action execution time, action finish time")
  public void testExecutionAndFinishTime() {
    apiStep.createAction("sleep -ms 7500");
    actionsStep.refreshPage();
    tableStep.checkTableRowsCountIs(1);
    actionsStep.openFirstActionDetails();
    actionsDetailsStep.checkExecutionAndFinishTimeForRunningAction();
  }

  @TmsLink("85966")
  @Story("Actions")
  @Test(description = "Check hosts assignment after Scheduled status")
  public void testHostAssignment() {
    int actionsQuantity = 20;
    for (int i = 0; i < actionsQuantity; i++) {
      apiStep.createAction("sleep -ms 10000");
    }
    actionsStep.refreshPage();
    actionsStep.checkHostAssignment();
  }

  @Step("Create actions for sorting test")
  private void prepareDataForSortingTest() {
    dataBaseStep.insertDataForActionSortTest();
    actionsStep.refreshPage();
    tableStep.checkTableRowsCountIs(4);
  }

  @Step("Create actions for filter test")
  private void prepareDataForFilterTest() {
    apiStep.createAction(TEST_ACTION_TEXT);
    dataBaseStep.insertDataForActionFilterTest();
    actionsStep.refreshPage();
    tableStep.checkTableRowsCountIs(2);
  }

  @Step("Create action for action details page test")
  private void prepareDataForActionDetailsPageTest() {
    dataBaseStep.insertDataForActionDetailsPageTest();
    actionsStep.refreshPage();
    tableStep.checkTableRowsCountIs(1);
  }
}
