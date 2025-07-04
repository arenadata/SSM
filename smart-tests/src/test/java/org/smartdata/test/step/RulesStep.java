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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.openqa.selenium.Keys;
import org.springframework.stereotype.Service;

import static com.codeborne.selenide.CollectionCondition.size;
import static org.smartdata.test.element.RulesPageElement.CREATE_RULE_BUTTON;
import static org.smartdata.test.element.RulesPageElement.CREATE_RULE_DIALOG_CANCEL_BUTTON;
import static org.smartdata.test.element.RulesPageElement.CREATE_RULE_DIALOG_CREATE_BUTTON;
import static org.smartdata.test.element.RulesPageElement.CREATE_RULE_DIALOG_INPUT;
import static org.smartdata.test.element.RulesPageElement.CREATE_RULE_DIALOG_TITLE;
import static org.smartdata.test.element.RulesPageElement.NO_DATA_TABLE_ROW;
import static org.smartdata.test.element.RulesPageElement.RULE_TABLE_ROWS;

@Slf4j
@Service
@RequiredArgsConstructor
public class RulesStep extends BaseWebStep {


  @Step("Click the \"Create rule\" button")
  public RulesStep clickCreateRuleButton() {
    waitAndClick(CREATE_RULE_BUTTON);
    return this;
  }

  @Step("Check Rules table is empty")
  public RulesStep checkRulesTableIsEmpty() {
    waitVisibility(NO_DATA_TABLE_ROW);
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

  @Step("Insert rule text, TEMP STEP")
  // TODO remove after fix UI bug
  public RulesStep insertRuleTextWorkaround(String ruleText) {
    waitVisibility(CREATE_RULE_DIALOG_INPUT);
    CREATE_RULE_DIALOG_INPUT.sendKeys(Keys.chord(Keys.CONTROL, "a"));
    CREATE_RULE_DIALOG_INPUT.sendKeys(ruleText);
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

  @Step("Check row quantity in the table")
  public RulesStep checkRuleRowsCount(int count) {
    RULE_TABLE_ROWS.shouldHave(size(count));
    return this;
  }
}
