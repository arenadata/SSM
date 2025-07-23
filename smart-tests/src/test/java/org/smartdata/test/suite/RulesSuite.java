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
import org.smartdata.test.step.ApiStep;
import org.smartdata.test.step.LoginStep;
import org.smartdata.test.step.MenuStep;
import org.smartdata.test.step.PaginationStep;
import org.smartdata.test.step.RulesStep;
import org.smartdata.test.step.TableStep;
import org.springframework.beans.factory.annotation.Autowired;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.smartdata.test.element.PaginationElement.PageSize.FIFTY;
import static org.smartdata.test.element.PaginationElement.PageSize.HUNDRED;
import static org.smartdata.test.element.PaginationElement.PageSize.TEN;
import static org.smartdata.test.element.PaginationElement.PageSize.THIRTY;
import static org.smartdata.test.element.RulesPageElement.RulesTableColumn.ID;
import static org.smartdata.test.element.RulesPageElement.RulesTableColumn.RULE_TEXT;
import static org.smartdata.test.element.RulesPageElement.RulesTableColumn.STATUS;
import static org.smartdata.test.model.RuleStatus.DISABLED;

@Feature("Rules page")
public class RulesSuite extends SsmBaseSuite {
  private static final String TEST_RULE_TEXT = "file : every 1h | path matches \"/test\" | list";

  @Autowired
  private LoginStep loginStep;

  @Autowired
  private MenuStep menuStep;

  @Autowired
  private RulesStep rulesStep;

  @Autowired
  private TableStep tableStep;

  @Autowired
  private PaginationStep paginationStep;

  @Autowired
  private ApiStep apiStep;


  @BeforeMethod
  public void openPage() {
    loginStep.loginAs(UserRole.OWNER);
    menuStep.openRulesPage();
  }

  @TmsLink("90589")
  @Story("Rules")
  @Test(description = "Check `Create rule` button")
  public void testCreateRuleButton() {
    tableStep.checkTableIsEmpty();
    rulesStep.clickCreateRuleButton()
        .checkEditorVisible()
        .insertRuleText(TEST_RULE_TEXT)
        .clickCancelButton()
        .checkEditorNotVisible()
        .refreshPage();
    tableStep.checkTableIsEmpty();
    rulesStep.clickCreateRuleButton()
        .insertRuleText(TEST_RULE_TEXT)
        .clickCreateButton();
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(RULE_TEXT, TEST_RULE_TEXT)
        .checkColumnValueInFirstRow(STATUS, DISABLED.getText());
  }

  @TmsLink("90213")
  @Story("Rules")
  @Test(description = "Check pagination")
  public void testPagination() {
    tableStep.checkTableIsEmpty();
    for (int i = 0; i < 101; i++) {
      apiStep.createRule(TEST_RULE_TEXT);
    }
    rulesStep.refreshPage();
    rulesStep.checkRulesCounter(101);
    paginationStep.checkShowPerPageValue(TEN);
    tableStep.checkTableRowsCountIs(TEN.getSize())
        .checkColumnValuesInFirstAndLastRow(ID, "101", "92");
    paginationStep.checkNumberedButtonIsSelected("1")
        .checkNumberedButtonIsVisible("11")
        .checkNumberedButtonsAmount(9)
        .checkAllNumberedButtonsIsEnabled()
        .checkPreviousPageButtonIsDisabled()
        .checkNextPageButtonIsEnabled()
        .checkLastPageButtonIsEnabled()
        .clickOnNextPageButton()
        .checkNumberedButtonIsSelected("2")
        .checkPreviousPageButtonIsEnabled();
    tableStep.checkTableRowsCountIs(TEN.getSize())
        .checkColumnValuesInFirstAndLastRow(ID, "91", "82");
    paginationStep.clickOnPreviousPageButton()
        .checkNumberedButtonIsSelected("1");
    tableStep.checkTableRowsCountIs(TEN.getSize())
        .checkColumnValuesInFirstAndLastRow(ID, "101", "92");
    paginationStep.clickOnLastPageButton()
        .checkNumberedButtonIsSelected("11")
        .checkNextPageButtonIsDisabled()
        .checkLastPageButtonIsDisabled();
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(ID, "1");
    paginationStep.clickOnExtendPagesButton()
        .checkNumberedButtonIsSelected("6");
    tableStep.checkTableRowsCountIs(TEN.getSize())
        .checkColumnValuesInFirstAndLastRow(ID, "51", "42");
    paginationStep.clickOnNumberedPageButton("4")
        .checkNumberedButtonIsSelected("4");
    tableStep.checkTableRowsCountIs(TEN.getSize())
        .checkColumnValuesInFirstAndLastRow(ID, "71", "62");
    paginationStep.setShowPerPageOption(THIRTY)
        .checkNumberedButtonsAmount(4)
        .checkShowPerPageValue(THIRTY);
    tableStep.checkTableRowsCountIs(THIRTY.getSize())
        .checkColumnValuesInFirstAndLastRow(ID, "101", "72");
    paginationStep.setShowPerPageOption(FIFTY)
        .checkNumberedButtonsAmount(3)
        .checkShowPerPageValue(FIFTY);
    tableStep.checkTableRowsCountIs(FIFTY.getSize())
        .checkColumnValuesInFirstAndLastRow(ID, "101", "52");
    paginationStep.setShowPerPageOption(HUNDRED)
        .checkNumberedButtonsAmount(2)
        .checkShowPerPageValue(HUNDRED);
    tableStep.checkTableRowsCountIs(HUNDRED.getSize())
        .checkColumnValuesInFirstAndLastRow(ID, "101", "2");
  }
}
