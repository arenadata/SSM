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
import org.openqa.selenium.WebElement;
import org.smartdata.test.element.PaginationElement;
import org.smartdata.test.model.TableColumn;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

import static com.codeborne.selenide.CollectionCondition.allMatch;
import static com.codeborne.selenide.Condition.exactText;
import static com.codeborne.selenide.Condition.exactValue;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.smartdata.test.element.PaginationElement.EXTEND_PAGES_BUTTON;
import static org.smartdata.test.element.PaginationElement.LAST_PAGE_BUTTON;
import static org.smartdata.test.element.PaginationElement.NEXT_PAGE_BUTTON;
import static org.smartdata.test.element.PaginationElement.PAGINATION_NUMBERED_BUTTONS;
import static org.smartdata.test.element.PaginationElement.PAGINATION_PER_PAGE_INPUT;
import static org.smartdata.test.element.PaginationElement.PREV_PAGE_BUTTON;
import static org.smartdata.test.element.PaginationElement.PageSize.FIFTY;
import static org.smartdata.test.element.PaginationElement.PageSize.HUNDRED;
import static org.smartdata.test.element.PaginationElement.PageSize.TEN;
import static org.smartdata.test.element.PaginationElement.PageSize.THIRTY;
import static org.smartdata.test.element.PaginationElement.SHOW_PER_PAGE_OPTIONS;
import static org.smartdata.test.element.PaginationElement.SHOW_PER_PAGE_SELECT;
import static org.smartdata.test.element.PaginationElement.getNumberedButtonByPageNum;

@Slf4j
@Service
public class PaginationStep extends BaseWebStep {

  @Autowired
  private TableStep tableStep;

  @Step("Check {pageNum} page button is selected")
  public PaginationStep checkNumberedButtonIsSelected(String pageNum) {
    SelenideElement numberedButton = getNumberedButtonByPageNum(pageNum);
    waitVisibility(numberedButton);
    assertThat(numberedButton.getAttribute("class"), containsString("is-active"));
    return this;
  }

  @Step("Check {pageNum} page button is visible")
  public PaginationStep checkNumberedButtonIsVisible(String pageNum) {
    waitVisibility(getNumberedButtonByPageNum(pageNum));
    return this;
  }

  @Step("Check all page buttons are visible and selected")
  public PaginationStep checkAllNumberedButtonsIsEnabled() {
    PAGINATION_NUMBERED_BUTTONS.should(allMatch("All numbered buttons should be visible", WebElement::isDisplayed));
    PAGINATION_NUMBERED_BUTTONS.should(allMatch("All numbered buttons should be enabled", WebElement::isEnabled));
    return this;
  }

  @Step("Check that there are {expectedAmount} numbered pagination buttons on the page")
  public PaginationStep checkNumberedButtonsAmount(int expectedAmount) {
    checkSize(PAGINATION_NUMBERED_BUTTONS, expectedAmount);
    return this;
  }

  @Step("Check 'Next page' button is enabled")
  public PaginationStep checkNextPageButtonIsEnabled() {
    isEnabled(NEXT_PAGE_BUTTON);
    return this;
  }

  @Step("Check 'Next page' button is disabled")
  public PaginationStep checkNextPageButtonIsDisabled() {
    isDisabled(NEXT_PAGE_BUTTON);
    return this;
  }

  @Step("Check 'Previous page' button is enabled")
  public PaginationStep checkPreviousPageButtonIsEnabled() {
    isEnabled(PREV_PAGE_BUTTON);
    return this;
  }

  @Step("Check 'Previous page' button is disabled")
  public PaginationStep checkPreviousPageButtonIsDisabled() {
    isDisabled(PREV_PAGE_BUTTON);
    return this;
  }

  @Step("Check 'Last page' button is enabled")
  public PaginationStep checkLastPageButtonIsEnabled() {
    isEnabled(LAST_PAGE_BUTTON);
    return this;
  }

  @Step("Check 'Last page' button is disabled")
  public PaginationStep checkLastPageButtonIsDisabled() {
    isDisabled(LAST_PAGE_BUTTON);
    return this;
  }

  @Step("Click on 'Next page' button")
  public PaginationStep clickOnNextPageButton() {
    waitAndClick(NEXT_PAGE_BUTTON);
    return this;
  }

  @Step("Click on 'Previous page' button")
  public PaginationStep clickOnPreviousPageButton() {
    waitAndClick(PREV_PAGE_BUTTON);
    return this;
  }

  @Step("Click on 'Last page' button")
  public PaginationStep clickOnLastPageButton() {
    waitAndClick(LAST_PAGE_BUTTON);
    return this;
  }

  @Step("Click on 'Extend pages' button")
  public PaginationStep clickOnExtendPagesButton() {
    waitAndClick(EXTEND_PAGES_BUTTON);
    return this;
  }

  @Step("Click on {pageNum} page button")
  public PaginationStep clickOnNumberedPageButton(String pageNum) {
    waitAndClick(getNumberedButtonByPageNum(pageNum));
    return this;
  }

  @Step("Check selected 'Show per page' value")
  public PaginationStep checkShowPerPageValue(PaginationElement.PageSize pageSize) {
    PAGINATION_PER_PAGE_INPUT.shouldHave(exactValue(pageSize.getOptionName()));
    return this;
  }

  @Step("Set 'Show per page' value")
  public PaginationStep setShowPerPageOption(PaginationElement.PageSize pageSize) {
    waitAndClick(SHOW_PER_PAGE_SELECT);
    waitAndClick(SHOW_PER_PAGE_OPTIONS.find(exactText(pageSize.getOptionName())));
    return this;
  }

  @Step("Check pagination table of the page")
  public void checkPaginationFixture(TableColumn tableColumn, List<String> testColumnValues) {
    // testColumnValues must be ordered as UI shown
    assertThat("testColumnValues size must be 101", testColumnValues.size(), is(101));
    // First page check
    checkNumberedButtonIsSelected("1")
        .checkNumberedButtonIsVisible("11")
        .checkNumberedButtonsAmount(9)
        .checkAllNumberedButtonsIsEnabled()
        .checkPreviousPageButtonIsDisabled()
        .checkNextPageButtonIsEnabled()
        .checkLastPageButtonIsEnabled()
        .checkShowPerPageValue(TEN);
    tableStep.checkTableRowsCountIs(TEN.getSize())
        .checkColumnValues(tableColumn, getExpectedValues(testColumnValues, 1, TEN.getSize()));
    // 'Next page' button check
    clickOnNextPageButton()
        .checkNumberedButtonIsSelected("2")
        .checkAllNumberedButtonsIsEnabled()
        .checkNextPageButtonIsEnabled()
        .checkLastPageButtonIsEnabled()
        .checkPreviousPageButtonIsEnabled();
    tableStep.checkTableRowsCountIs(TEN.getSize())
        .checkColumnValues(tableColumn, getExpectedValues(testColumnValues, 2, TEN.getSize()));
    // 'Previous page' button check
    clickOnPreviousPageButton()
        .checkNumberedButtonIsSelected("1");
    tableStep.checkTableRowsCountIs(TEN.getSize())
        .checkColumnValues(tableColumn, getExpectedValues(testColumnValues, 1, TEN.getSize()));
    // 'Last page' button check
    clickOnLastPageButton()
        .checkNumberedButtonIsSelected("11")
        .checkAllNumberedButtonsIsEnabled()
        .checkNextPageButtonIsDisabled()
        .checkLastPageButtonIsDisabled()
        .checkPreviousPageButtonIsEnabled();
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(tableColumn, "1");
    // 'Extend pages' button check
    clickOnExtendPagesButton()
        .checkNumberedButtonIsSelected("6");
    tableStep.checkTableRowsCountIs(TEN.getSize())
        .checkColumnValues(tableColumn, getExpectedValues(testColumnValues, 6, TEN.getSize()));
    // Numbered button check
    clickOnNumberedPageButton("4")
        .checkNumberedButtonIsSelected("4");
    tableStep.checkTableRowsCountIs(TEN.getSize())
        .checkColumnValues(tableColumn, getExpectedValues(testColumnValues, 4, TEN.getSize()));
    // 'Show per page' options check
    setShowPerPageOption(THIRTY)
        .checkNumberedButtonsAmount(4)
        .checkShowPerPageValue(THIRTY);
    tableStep.checkTableRowsCountIs(THIRTY.getSize())
        .checkColumnValues(tableColumn, getExpectedValues(testColumnValues, 1, THIRTY.getSize()));
    setShowPerPageOption(FIFTY)
        .checkNumberedButtonsAmount(3)
        .checkShowPerPageValue(FIFTY);
    tableStep.checkTableRowsCountIs(FIFTY.getSize())
        .checkColumnValues(tableColumn, getExpectedValues(testColumnValues, 1, FIFTY.getSize()));
    setShowPerPageOption(HUNDRED)
        .checkNumberedButtonsAmount(2)
        .checkShowPerPageValue(HUNDRED);
    tableStep.checkTableRowsCountIs(HUNDRED.getSize())
        .checkColumnValues(tableColumn, getExpectedValues(testColumnValues, 1, HUNDRED.getSize()));
  }

  private List<String> getExpectedValues(List<String> testColumnValues, int pageNumber, int pageSize) {
    if (pageNumber < 1 || pageSize < 1) {
      throw new IllegalArgumentException("Invalid argument(s)");
    }
    int fromIndex = (pageNumber - 1) * pageSize;
    if (fromIndex >= testColumnValues.size()) {
      return Collections.emptyList();
    }
    int toIndex = Math.min(fromIndex + pageSize, testColumnValues.size());
    return testColumnValues.subList(fromIndex, toIndex);
  }
}
