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
import org.smartdata.test.step.ActionsStep;
import org.smartdata.test.step.DataBaseStep;
import org.smartdata.test.step.LoginStep;
import org.smartdata.test.step.MenuStep;
import org.smartdata.test.step.TableStep;
import org.smartdata.test.util.comparator.ActionStatusComparator;
import org.smartdata.test.util.comparator.DashIsMaxComparator;
import org.springframework.beans.factory.annotation.Autowired;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.ACTION;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.CREATE_TIME;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.FINISH_TIME;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.HOST;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.ID;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.STATUS;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.TYPE;
import static org.smartdata.test.model.ActionStatus.SUCCESSFUL;

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

  @Step("Create rules for sorting test")
  private void prepareDataForSortingTest() {
    dataBaseStep.insertDataForActionSortTest();
    actionsStep.refreshPage();
  }
}
