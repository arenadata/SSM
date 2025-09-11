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

import com.codeborne.selenide.SelenideElement;
import io.arenadata.test.step.BaseWebStep;
import io.qameta.allure.Step;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import static com.codeborne.selenide.Condition.attributeMatching;
import static org.smartdata.test.element.ActionsDetailsPageElement.ACTION_DETAILS_LOG_BUTTON;
import static org.smartdata.test.element.ActionsDetailsPageElement.ACTION_DETAILS_LOG_VIEW;
import static org.smartdata.test.element.ActionsDetailsPageElement.ACTION_DETAILS_RESULT_BUTTON;
import static org.smartdata.test.element.ActionsDetailsPageElement.ActionsDetailsTableColumn.CREATE_TIME;
import static org.smartdata.test.element.ActionsDetailsPageElement.ActionsDetailsTableColumn.FINISH_TIME;
import static org.smartdata.test.element.ActionsDetailsPageElement.ActionsDetailsTableColumn.HOST;
import static org.smartdata.test.element.ActionsDetailsPageElement.ActionsDetailsTableColumn.ID;
import static org.smartdata.test.element.ActionsDetailsPageElement.ActionsDetailsTableColumn.RUNNING_TIME;
import static org.smartdata.test.element.ActionsDetailsPageElement.ActionsDetailsTableColumn.STATUS;
import static org.smartdata.test.element.ActionsDetailsPageElement.ActionsDetailsTableColumn.TYPE;
import static org.smartdata.test.element.ActionsDetailsPageElement.HEADER_RUNNING_ICON;
import static org.smartdata.test.element.ActionsDetailsPageElement.HEADER_SUCCESSFUL_ICON;
import static org.smartdata.test.element.ActionsDetailsPageElement.HEADER_TITLE_ACTION;
import static org.smartdata.test.element.ActionsDetailsPageElement.HEADER_TITLE_PARAMS;
import static org.smartdata.test.element.ActionsPageElement.REPEAT_ACTION_BUTTON_XPATH;
import static org.smartdata.test.element.ActionsPageElement.REPEAT_ACTION_DIALOG;
import static org.smartdata.test.element.ActionsPageElement.REPEAT_ACTION_DIALOG_RUN_BUTTON;
import static org.smartdata.test.element.TableElement.BLUE_STATUS_MARKER_XPATH;
import static org.smartdata.test.element.TableElement.GREEN_STATUS_MARKER_XPATH;
import static org.smartdata.test.element.TableElement.getTableRows;
import static org.smartdata.test.model.ActionStatus.RUNNING;
import static org.smartdata.test.model.ActionStatus.SUCCESSFUL;
import static org.smartdata.test.util.constant.CommonConstants.DATE_TIME_UI_PATTERN;
import static org.smartdata.test.util.constant.CommonConstants.RUNNING_TIME_PATTERN;
import static org.smartdata.test.util.constant.CommonConstants.TABLE_EMPTY_VALUE;


@Slf4j
@Service
public class ActionsDetailsStep extends BaseWebStep {

  @Autowired
  private TableStep tableStep;

  @Step("Check 'Action Details' table row with prepared values")
  public ActionsDetailsStep checkFakeActionDetailsTableRow() {
    tableStep.checkColumnValueInFirstRow(ID, "888")
        .checkColumnValueInFirstRow(CREATE_TIME, "11/08/2025 13:46:40")
        .checkColumnValueInFirstRow(FINISH_TIME, "11/08/2025 13:46:40")
        .checkColumnValueInFirstRow(RUNNING_TIME, "888ms")
        .checkColumnValueInFirstRow(STATUS, SUCCESSFUL.getText())
        .checkColorStatusMarkerInFirstRow(STATUS, GREEN_STATUS_MARKER_XPATH)
        .checkColumnValueInFirstRow(TYPE, "User action")
        .checkColumnValueInFirstRow(HOST, "FAKE HOST");
    return this;
  }

  @Step("Check 'Action Details' header info")
  public ActionsDetailsStep checkActionDetailsHeaderInfo(String action, String params, SelenideElement stateIcon) {
    waitTextEquals(HEADER_TITLE_ACTION, action);
    waitTextEquals(HEADER_TITLE_PARAMS, params);
    waitVisibility(stateIcon);
    return this;
  }

  @Step("Check 'Action Details' log view")
  public ActionsDetailsStep checkActionDetailsLogViewValues(String result, String log) {
    waitVisibility(ACTION_DETAILS_RESULT_BUTTON);
    ACTION_DETAILS_RESULT_BUTTON.should(attributeMatching("class", ".*active.*"));
    waitTextEquals(ACTION_DETAILS_LOG_VIEW, result);
    waitAndClick(ACTION_DETAILS_LOG_BUTTON);
    ACTION_DETAILS_LOG_BUTTON.should(attributeMatching("class", ".*active.*"));
    waitTextEquals(ACTION_DETAILS_LOG_VIEW, log);
    return this;
  }

  @Step("Repeat action on 'Action Details' page")
  public ActionsDetailsStep repeatAction() {
    waitAndClick(getTableRows().first().$x(REPEAT_ACTION_BUTTON_XPATH));
    waitVisibility(REPEAT_ACTION_DIALOG);
    waitAndClick(REPEAT_ACTION_DIALOG_RUN_BUTTON);
    return this;
  }

  @Step("Check execution and finish time for running action")
  public ActionsDetailsStep checkExecutionAndFinishTimeForRunningAction() {
    waitVisibility(HEADER_RUNNING_ICON);
    tableStep.checkColumnValueInFirstRow(STATUS, RUNNING.getText())
        .checkColorStatusMarkerInFirstRow(STATUS, BLUE_STATUS_MARKER_XPATH)
        .checkColumnValueInFirstRow(FINISH_TIME, TABLE_EMPTY_VALUE)
        .checkColumnValueInFirstRowMatchPattern(RUNNING_TIME, RUNNING_TIME_PATTERN)
        .checkColumnValueInFirstRow(STATUS, SUCCESSFUL.getText())
        .checkColorStatusMarkerInFirstRow(STATUS, GREEN_STATUS_MARKER_XPATH)
        .checkColumnValueInFirstRowMatchPattern(FINISH_TIME, DATE_TIME_UI_PATTERN)
        .checkColumnValueInFirstRowMatchPattern(RUNNING_TIME, RUNNING_TIME_PATTERN);
    waitVisibility(HEADER_SUCCESSFUL_ICON);
    return this;
  }
}
