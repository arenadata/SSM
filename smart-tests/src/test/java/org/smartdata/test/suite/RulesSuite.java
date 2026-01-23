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
import org.smartdata.test.step.ApiStep;
import org.smartdata.test.step.DataBaseStep;
import org.smartdata.test.step.LoginStep;
import org.smartdata.test.step.MenuStep;
import org.smartdata.test.step.PaginationStep;
import org.smartdata.test.step.RulesStep;
import org.smartdata.test.step.TableStep;
import org.smartdata.test.util.comparator.UiDateTimeComparator;
import org.springframework.beans.factory.annotation.Autowired;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.smartdata.test.element.RulesPageElement.DELETE_RULE_BUTTON;
import static org.smartdata.test.element.RulesPageElement.RulesTableColumn.CHECKED_NUMBER;
import static org.smartdata.test.element.RulesPageElement.RulesTableColumn.CMDLETS_GENERATED;
import static org.smartdata.test.element.RulesPageElement.RulesTableColumn.ID;
import static org.smartdata.test.element.RulesPageElement.RulesTableColumn.LAST_CHECK_TIME;
import static org.smartdata.test.element.RulesPageElement.RulesTableColumn.RULE_TEXT;
import static org.smartdata.test.element.RulesPageElement.RulesTableColumn.STATUS;
import static org.smartdata.test.element.RulesPageElement.RulesTableColumn.SUBMISSION_TIME;
import static org.smartdata.test.element.RulesPageElement.START_RULE_BUTTON;
import static org.smartdata.test.element.RulesPageElement.STOP_RULE_BUTTON;
import static org.smartdata.test.element.TableElement.GRAY_STATUS_MARKER_XPATH;
import static org.smartdata.test.element.TableElement.GREEN_STATUS_MARKER_XPATH;
import static org.smartdata.test.model.RuleStatus.ACTIVE;
import static org.smartdata.test.model.RuleStatus.DISABLED;
import static org.smartdata.test.util.constant.CommonConstants.PAGINATION_QUANTITY;

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

  @Autowired
  private DataBaseStep dataBaseStep;

  @BeforeMethod
  public void testPrepare() {
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
        .checkEditorNotVisible();
    tableStep.checkTableIsEmpty();
    rulesStep.clickCreateRuleButton()
        .checkEditorVisible()
        .checkEditorEmpty()
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
    List<String> rulesIds = prepareDataForPaginationTest();
    paginationStep.checkPaginationFixture(ID, rulesIds);
  }

  @TmsLink("90539")
  @Story("Rules")
  @Test(description = "Check sorting")
  public void testSorting() {
    prepareDataForSortingTest();
    tableStep.checkDefaultSorting(ID)
        .checkSorting(SUBMISSION_TIME, new UiDateTimeComparator())
        .checkSorting(LAST_CHECK_TIME, new UiDateTimeComparator())
        .checkSorting(CHECKED_NUMBER)
        .checkSorting(CMDLETS_GENERATED)
        .checkSorting(STATUS);
  }

  @TmsLink("90212")
  @Story("Rules")
  @Test(description = "Check filtration")
  public void testFiltration() {
    prepareDataForFilterTest();
    rulesStep.checkRuleTextFiltration()
        .checkSubmissionTimeFiltration()
        .checkLastCheckTimeFiltration()
        .checkStatusFiltration();
  }

  @TmsLink("90541")
  @Story("Rules")
  @Test(description = "Check actions")
  public void testActions() {
    apiStep.createRule(TEST_RULE_TEXT);
    rulesStep.refreshPage();
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(STATUS, DISABLED.getText())
        .checkColorStatusMarkerInFirstRow(STATUS, GRAY_STATUS_MARKER_XPATH);
    rulesStep.checkRuleActionButtonFixture(START_RULE_BUTTON);
    tableStep.checkColumnValueInFirstRow(STATUS, ACTIVE.getText())
        .checkColorStatusMarkerInFirstRow(STATUS, GREEN_STATUS_MARKER_XPATH);
    rulesStep.checkRuleActionButtonFixture(STOP_RULE_BUTTON);
    tableStep.checkColumnValueInFirstRow(STATUS, DISABLED.getText())
        .checkColorStatusMarkerInFirstRow(STATUS, GRAY_STATUS_MARKER_XPATH);
    rulesStep.checkRuleActionButtonFixture(DELETE_RULE_BUTTON);
    tableStep.checkTableRowsCountIs(0);
  }

  @Step("Create rules for pagination test")
  private List<String> prepareDataForPaginationTest() {
    List<String> rulesIds = new ArrayList<>();
    tableStep.checkTableIsEmpty();
    for (int i = 1; i <= PAGINATION_QUANTITY; i++) {
      apiStep.createRule(TEST_RULE_TEXT);
      rulesIds.add(String.valueOf(i));
    }
    rulesStep.refreshPage();
    rulesStep.checkRulesCounter(PAGINATION_QUANTITY);
    Collections.reverse(rulesIds);
    return rulesIds;
  }

  @Step("Create rules for sorting test")
  private void prepareDataForSortingTest() {
    dataBaseStep.insertDataForRulesSortTest();
    rulesStep.refreshPage();
  }

  @Step("Create rules for filter test")
  private void prepareDataForFilterTest() {
    dataBaseStep.insertDataForRulesFilterTest();
    rulesStep.refreshPage();
    tableStep.checkTableRowsCountIs(2);
  }
}
