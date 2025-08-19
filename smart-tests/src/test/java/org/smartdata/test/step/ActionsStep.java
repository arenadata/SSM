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
import com.codeborne.selenide.WebDriverRunner;
import io.arenadata.test.step.BaseWebStep;
import io.qameta.allure.Step;
import lombok.extern.slf4j.Slf4j;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.devtools.DevTools;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

import static com.codeborne.selenide.Condition.visible;
import static java.time.Duration.ofMillis;
import static java.time.ZoneOffset.UTC;
import static java.time.temporal.ChronoUnit.MILLIS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.byLessThan;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.ACTION;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.CREATE_TIME;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.FINISH_TIME;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.HOST;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.STATUS;
import static org.smartdata.test.element.ActionsPageElement.ActionsTableColumn.TYPE;
import static org.smartdata.test.element.ActionsPageElement.SUBMIT_ACTION_BUTTON;
import static org.smartdata.test.element.ActionsPageElement.SUBMIT_ACTION_DIALOG;
import static org.smartdata.test.element.ActionsPageElement.SUBMIT_ACTION_DIALOG_CANCEL_BUTTON;
import static org.smartdata.test.element.ActionsPageElement.SUBMIT_ACTION_DIALOG_CREATE_BUTTON;
import static org.smartdata.test.element.ActionsPageElement.SUBMIT_ACTION_DIALOG_INPUT;
import static org.smartdata.test.model.ActionStatus.SUCCESSFUL;

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
    tableFilterPopupStep.clickMultiselectPopupCheckbox("SSMAgent@hadoop-datanode.demo");
    tableFilterPopupStep.clickMultiselectPopupCheckbox("ActiveSSMServer@ssm-server.demo");
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

  public ActionsStep checkFrequency(SelenideElement element, long timeout) {
    LocalDateTime start = LocalDateTime.now();
    element.shouldBe(visible, ofMillis(timeout));
    LocalDateTime end = LocalDateTime.now();
    assertThat(start).isCloseTo(end, byLessThan(timeout, MILLIS));
    ChromeDriver driver = (ChromeDriver) WebDriverRunner.getWebDriver();
    DevTools devTools = driver.getDevTools();
    devTools.createSession();
    return this;
  }


}
