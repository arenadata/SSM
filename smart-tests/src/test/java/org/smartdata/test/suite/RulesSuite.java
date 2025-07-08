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
import io.qameta.allure.Story;
import io.qameta.allure.TmsLink;
import org.smartdata.test.element.RulesPageElement;
import org.smartdata.test.model.RuleStatus;
import org.smartdata.test.step.LoginStep;
import org.smartdata.test.step.MenuStep;
import org.smartdata.test.step.RulesStep;
import org.smartdata.test.step.TableStep;
import org.springframework.beans.factory.annotation.Autowired;
import org.testng.annotations.Test;

@Feature("Rules page tests")
public class RulesSuite extends SsmBaseSuite {
  private static final String RULE_TEXT = "file : every 1h | path matches \"/test\" | list";

  @Autowired
  private LoginStep loginStep;

  @Autowired
  private MenuStep menuStep;

  @Autowired
  private RulesStep rulesStep;

  @Autowired
  private TableStep tableStep;

  @TmsLink("90589")
  @Story("Rules")
  @Test(description = "Check `Create rule` button")
  public void testCreateRuleButton() {
    loginStep.loginAs(UserRole.OWNER);
    menuStep.openRulesPage();
    tableStep.checkTableIsEmpty(false);
    rulesStep.clickCreateRuleButton()
        .checkEditorVisible()
        .insertRuleText(RULE_TEXT)
        .clickCancelButton()
        .checkEditorNotVisible();
    tableStep.checkTableIsEmpty(true);
    rulesStep.clickCreateRuleButton()
        .insertRuleText(RULE_TEXT)
        .clickCreateButton();
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(
            RulesPageElement.RulesTableColumn.RULE_TEXT.getIndex(), RULE_TEXT)
        .checkColumnValueInFirstRow(
            RulesPageElement.RulesTableColumn.STATUS.getIndex(), RuleStatus.DISABLED.getText());
  }
}
