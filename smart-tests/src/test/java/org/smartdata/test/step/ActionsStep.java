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
package org.smartdata.test.step;

import io.arenadata.test.step.BaseWebStep;
import io.qameta.allure.Step;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

import static com.codeborne.selenide.Condition.exactText;
import static com.codeborne.selenide.Condition.or;
import static java.time.ZoneOffset.UTC;
import static org.smartdata.test.element.ActionsPageElement.ACTION_DETAILS_LINK_XPATH;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.ACTION;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.CREATE_TIME;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.FINISH_TIME;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.HOST;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.ID;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.STATUS;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.TYPE;
import static org.smartdata.test.element.ActionsPageElement.REPEAT_ACTION_BUTTON_XPATH;
import static org.smartdata.test.element.ActionsPageElement.REPEAT_ACTION_DIALOG;
import static org.smartdata.test.element.ActionsPageElement.REPEAT_ACTION_DIALOG_CANCEL_BUTTON;
import static org.smartdata.test.element.ActionsPageElement.REPEAT_ACTION_DIALOG_INPUT;
import static org.smartdata.test.element.ActionsPageElement.REPEAT_ACTION_DIALOG_RUN_BUTTON;
import static org.smartdata.test.element.ActionsPageElement.SUBMIT_ACTION_BUTTON;
import static org.smartdata.test.element.ActionsPageElement.SUBMIT_ACTION_DIALOG;
import static org.smartdata.test.element.ActionsPageElement.SUBMIT_ACTION_DIALOG_CANCEL_BUTTON;
import static org.smartdata.test.element.ActionsPageElement.SUBMIT_ACTION_DIALOG_CREATE_BUTTON;
import static org.smartdata.test.element.ActionsPageElement.SUBMIT_ACTION_DIALOG_INPUT;
import static org.smartdata.test.element.TableElement.getCellInFirstRow;
import static org.smartdata.test.element.TableElement.getTableRows;
import static org.smartdata.test.model.ActionStatus.RUNNING;
import static org.smartdata.test.model.ActionStatus.SCHEDULED;
import static org.smartdata.test.model.ActionStatus.SUCCESSFUL;
import static org.smartdata.test.model.SortOrder.DESC;
import static org.smartdata.test.util.constant.CommonConstants.DATANODE_HOST_NAME;
import static org.smartdata.test.util.constant.CommonConstants.SSM_SERVER_HOST_NAME;
import static org.smartdata.test.util.constant.CommonConstants.TABLE_EMPTY_VALUE;

@Slf4j
@Service
public class ActionsStep extends BaseWebStep {
  private static final String TEST_ACTION_TEXT = "sleep -ms 100";

  @Autowired
  private TableStep tableStep;

  @Autowired
  private TableFilterPopupStep tableFilterPopupStep;

  @Step("Check 'Run' button on submit action dialog")
  public ActionsStep checkSubmitDialogRunButton(String actionText) {
    waitAndClick(SUBMIT_ACTION_BUTTON);
    waitVisibility(SUBMIT_ACTION_DIALOG);
    waitAndWrite(SUBMIT_ACTION_DIALOG_INPUT, actionText);
    waitAndClick(SUBMIT_ACTION_DIALOG_CREATE_BUTTON);
    waitDisappear(SUBMIT_ACTION_DIALOG);
    return this;
  }

  @Step("Check 'Cancel' button on submit action dialog")
  public ActionsStep checkSubmitDialogCancelButton(String actionText) {
    waitAndClick(SUBMIT_ACTION_BUTTON);
    waitVisibility(SUBMIT_ACTION_DIALOG);
    waitAndWrite(SUBMIT_ACTION_DIALOG_INPUT, actionText);
    waitAndClick(SUBMIT_ACTION_DIALOG_CANCEL_BUTTON);
    waitDisappear(SUBMIT_ACTION_DIALOG);
    return this;
  }

  @Step("Check filtration by 'Action Text'")
  public ActionsStep checkActionTextFiltration() {
    tableStep.clickFilterButton(ACTION);
    tableFilterPopupStep.setTextPopupInput("sleep");
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(ACTION, TEST_ACTION_TEXT)
        .clickResetFilterButton()
        .checkTableRowsCountIs(2);
    return this;
  }

  @Step("Check filtration by 'Host'")
  public ActionsStep checkHostFiltration() {
    tableStep.clickFilterButton(HOST);
    tableFilterPopupStep.clickMultiselectPopupCheckbox(SSM_SERVER_HOST_NAME);
    tableFilterPopupStep.clickMultiselectPopupCheckbox(DATANODE_HOST_NAME);
    tableStep.clickFilterButton(HOST)
        .checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(ACTION, TEST_ACTION_TEXT)
        .clickResetFilterButton()
        .checkTableRowsCountIs(2);
    return this;
  }

  @Step("Check filtration by 'Create Time'")
  public ActionsStep checkCreateTimeFiltration() {
    tableStep.clickFilterButton(CREATE_TIME);
    tableFilterPopupStep.checkDataPickerRangeValues("now-1h", "now")
        .clickOnDataPickerApplyButton();
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(ACTION, TEST_ACTION_TEXT)
        .clickResetFilterButton()
        .checkTableRowsCountIs(2)
        .clickFilterButton(CREATE_TIME);
    tableFilterPopupStep.clickOnCalendarTabButton()
        .setDataPickerCalendarValues(LocalDateTime.now(UTC).minusHours(1), LocalDateTime.now(UTC))
        .clickOnDataPickerApplyButton();
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(ACTION, TEST_ACTION_TEXT)
        .clickResetFilterButton()
        .checkTableRowsCountIs(2);
    return this;
  }

  @Step("Check filtration by 'Finish Time'")
  public ActionsStep checkFinishTimeFiltration() {
    tableStep.clickFilterButton(FINISH_TIME);
    tableFilterPopupStep.checkDataPickerRangeValues("now-1h", "now")
        .clickOnDataPickerApplyButton();
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(ACTION, TEST_ACTION_TEXT)
        .clickResetFilterButton()
        .checkTableRowsCountIs(2)
        .clickFilterButton(FINISH_TIME);
    tableFilterPopupStep.clickOnCalendarTabButton()
        .setDataPickerCalendarValues(LocalDateTime.now(UTC).minusHours(1), LocalDateTime.now(UTC))
        .clickOnDataPickerApplyButton();
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(ACTION, TEST_ACTION_TEXT)
        .clickResetFilterButton()
        .checkTableRowsCountIs(2);
    return this;
  }

  @Step("Check filtration by 'Status'")
  public ActionsStep checkStatusFiltration() {
    tableStep.clickFilterButton(STATUS);
    tableFilterPopupStep.clickMultiselectPopupCheckbox(SUCCESSFUL.getText());
    tableStep.clickFilterButton(STATUS)
        .checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(ACTION, TEST_ACTION_TEXT)
        .clickResetFilterButton()
        .checkTableRowsCountIs(2);
    return this;
  }

  @Step("Check filtration by 'Type'")
  public ActionsStep checkTypeFiltration() {
    tableStep.clickFilterButton(TYPE);
    tableFilterPopupStep.clickMultiselectPopupCheckbox("User action");
    tableStep.clickFilterButton(TYPE)
        .checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(ACTION, TEST_ACTION_TEXT)
        .clickResetFilterButton()
        .checkTableRowsCountIs(2);
    return this;
  }

  @Step("Check 'Repeat Action' button")
  public ActionsStep checkRepeatActionButton() {
    waitAndClick(getTableRows().first().$x(REPEAT_ACTION_BUTTON_XPATH));
    waitVisibility(REPEAT_ACTION_DIALOG);
    waitTextEquals(REPEAT_ACTION_DIALOG_INPUT, TEST_ACTION_TEXT);
    waitAndClick(REPEAT_ACTION_DIALOG_CANCEL_BUTTON);
    waitDisappear(REPEAT_ACTION_DIALOG);
    waitAndClick(getTableRows().first().$x(REPEAT_ACTION_BUTTON_XPATH));
    waitAndClick(REPEAT_ACTION_DIALOG_RUN_BUTTON);
    tableStep.checkTableRowsCountIs(2);
    waitAndClick(getTableRows().first().$x(REPEAT_ACTION_BUTTON_XPATH));
    waitAndReWrite(REPEAT_ACTION_DIALOG_INPUT, TEST_ACTION_TEXT);
    waitAndClick(REPEAT_ACTION_DIALOG_RUN_BUTTON);
    tableStep.checkTableRowsCountIs(3)
        .checkAllColumnCellsTextEqual(3, ACTION, TEST_ACTION_TEXT)
        .checkAllColumnCellsTextEqual(3, STATUS, SUCCESSFUL.getText());
    return this;
  }

  @Step("Open 'Action Details' page for first action in table")
  public ActionsStep openFirstActionDetails() {
    waitAndClick(getCellInFirstRow(ACTION).$x(ACTION_DETAILS_LINK_XPATH));
    return this;
  }

  @Step("Check hosts assignment")
  public ActionsStep checkHostAssignment() {
    tableStep.checkSelectedSorting(ID, DESC);
    waitTextEquals(getCellInFirstRow(STATUS), SCHEDULED.getText());
    waitTextEquals(getCellInFirstRow(HOST), TABLE_EMPTY_VALUE);
    getCellInFirstRow(HOST).shouldHave(exactText(TABLE_EMPTY_VALUE));
    waitTextEquals(getCellInFirstRow(STATUS), RUNNING.getText());
    getCellInFirstRow(HOST).shouldHave(
        or("Check host name", exactText(SSM_SERVER_HOST_NAME), exactText(DATANODE_HOST_NAME)));
    waitTextEquals(getCellInFirstRow(STATUS), SUCCESSFUL.getText());
    getCellInFirstRow(HOST).shouldHave(
        or("Check host name", exactText(SSM_SERVER_HOST_NAME), exactText(DATANODE_HOST_NAME)));
    return this;
  }
}
