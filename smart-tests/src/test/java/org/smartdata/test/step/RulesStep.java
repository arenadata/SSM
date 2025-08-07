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

import java.time.LocalDateTime;

import static java.time.ZoneOffset.UTC;
import static org.smartdata.test.element.RulesPageElement.CREATE_RULE_BUTTON;
import static org.smartdata.test.element.RulesPageElement.CREATE_RULE_DIALOG_CANCEL_BUTTON;
import static org.smartdata.test.element.RulesPageElement.CREATE_RULE_DIALOG_CREATE_BUTTON;
import static org.smartdata.test.element.RulesPageElement.CREATE_RULE_DIALOG_INPUT;
import static org.smartdata.test.element.RulesPageElement.CREATE_RULE_DIALOG_TITLE;
import static org.smartdata.test.element.RulesPageElement.RULES_COUNTER_CARD;
import static org.smartdata.test.element.RulesPageElement.RULE_MODAL_DIALOG;
import static org.smartdata.test.element.RulesPageElement.RULE_MODAL_DIALOG_ACCEPT_BUTTON;
import static org.smartdata.test.element.RulesPageElement.RULE_MODAL_DIALOG_CANCEL_BUTTON;
import static org.smartdata.test.element.RulesPageElement.RulesTableColumn.ID;
import static org.smartdata.test.element.RulesPageElement.RulesTableColumn.LAST_CHECK_TIME;
import static org.smartdata.test.element.RulesPageElement.RulesTableColumn.RULE_TEXT;
import static org.smartdata.test.element.RulesPageElement.RulesTableColumn.STATUS;
import static org.smartdata.test.element.RulesPageElement.RulesTableColumn.SUBMISSION_TIME;
import static org.smartdata.test.model.RuleStatus.ACTIVE;

@Slf4j
@Service
public class RulesStep extends BaseWebStep {

  @Autowired
  private TableStep tableStep;

  @Autowired
  private TableFilterPopupStep tableFilterPopupStep;

  @Step("Click the \"Create rule\" button")
  public RulesStep clickCreateRuleButton() {
    waitAndClick(CREATE_RULE_BUTTON);
    return this;
  }

  @Step("Check Create Rule dialog is visible")
  public RulesStep checkEditorVisible() {
    waitVisibility(CREATE_RULE_DIALOG_TITLE);
    waitVisibility(CREATE_RULE_DIALOG_CREATE_BUTTON);
    waitVisibility(CREATE_RULE_DIALOG_CANCEL_BUTTON);
    return this;
  }

  @Step("Check Create Rule dialog is not visible")
  public RulesStep checkEditorNotVisible() {
    waitDisappear(CREATE_RULE_DIALOG_TITLE);
    waitDisappear(CREATE_RULE_DIALOG_CREATE_BUTTON);
    waitDisappear(CREATE_RULE_DIALOG_CANCEL_BUTTON);
    return this;
  }

  @Step("Insert rule text")
  public RulesStep insertRuleText(String ruleText) {
    waitAndWrite(CREATE_RULE_DIALOG_INPUT, ruleText);
    return this;
  }

  @Step("Click the Cancel button")
  public RulesStep clickCancelButton() {
    waitAndClick(CREATE_RULE_DIALOG_CANCEL_BUTTON);
    return this;
  }

  @Step("Click the Create button")
  public RulesStep clickCreateButton() {
    waitAndClick(CREATE_RULE_DIALOG_CREATE_BUTTON);
    return this;
  }

  @Step("Check rules counter value is {count}")
  public RulesStep checkRulesCounter(Integer count) {
    waitTextEquals(RULES_COUNTER_CARD, count.toString());
    return this;
  }

  @Step("Check filtration by 'Rule Text'")
  public RulesStep checkRuleTextFiltration() {
    tableStep.clickFilterButton(RULE_TEXT);
    tableFilterPopupStep.setTextPopupInput("sleep");
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(ID, "1")
        .clickResetFilterButton()
        .checkTableRowsCountIs(2);
    return this;
  }

  @Step("Check filtration by 'Submission Time'")
  public RulesStep checkSubmissionTimeFiltration() {
    tableStep.clickFilterButton(SUBMISSION_TIME);
    tableFilterPopupStep.checkDataPickerRangeValues("now-1h", "now")
        .clickOnDataPickerApplyButton();
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(ID, "1")
        .clickResetFilterButton()
        .checkTableRowsCountIs(2)
        .clickFilterButton(SUBMISSION_TIME);
    tableFilterPopupStep.clickOnCalendarTabButton()
        .setDataPickerCalendarValues(LocalDateTime.now(UTC).minusHours(1), LocalDateTime.now(UTC))
        .clickOnDataPickerApplyButton();
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(ID, "1")
        .clickResetFilterButton()
        .checkTableRowsCountIs(2);
    return this;
  }

  @Step("Check filtration by 'Last Check Time'")
  public RulesStep checkLastCheckTimeFiltration() {
    tableStep.clickFilterButton(LAST_CHECK_TIME);
    tableFilterPopupStep.checkDataPickerRangeValues("now-1h", "now")
        .clickOnDataPickerApplyButton();
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(ID, "1")
        .clickResetFilterButton()
        .checkTableRowsCountIs(2)
        .clickFilterButton(LAST_CHECK_TIME);
    tableFilterPopupStep.clickOnCalendarTabButton()
        .setDataPickerCalendarValues(LocalDateTime.now(UTC).minusHours(3), LocalDateTime.now(UTC).minusHours(1))
        .clickOnDataPickerApplyButton();
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(ID, "2")
        .clickResetFilterButton()
        .checkTableRowsCountIs(2);
    return this;
  }

  @Step("Check filtration by 'Status'")
  public RulesStep checkStatusFiltration() {
    tableStep.clickFilterButton(STATUS);
    tableFilterPopupStep.clickMultiselectPopupCheckbox(ACTIVE.getText());
    tableStep.clickFilterButton(STATUS)
        .checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(ID, "1")
        .clickResetFilterButton()
        .checkTableRowsCountIs(2);
    return this;
  }

  @Step("Check rule action button")
  public RulesStep checkRuleActionButtonFixture(SelenideElement actionButton) {
    waitAndClick(actionButton);
    waitAndClick(RULE_MODAL_DIALOG_CANCEL_BUTTON);
    waitDisappear(RULE_MODAL_DIALOG);
    waitAndClick(actionButton);
    waitAndClick(RULE_MODAL_DIALOG_ACCEPT_BUTTON);
    waitDisappear(RULE_MODAL_DIALOG);
    return this;
  }
}
