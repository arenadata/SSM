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
import static com.codeborne.selenide.Condition.attributeMatching;
import static com.codeborne.selenide.Condition.exactText;
import static com.codeborne.selenide.Condition.exactValue;
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
  public PaginationStep checkNumberedButtonIsSelected(int pageNum) {
    SelenideElement numberedButton = getNumberedButtonByPageNum(pageNum);
    waitVisibility(numberedButton);
    numberedButton.should(attributeMatching("class", ".*active.*"));
    return this;
  }

  @Step("Check all page buttons are visible and enabled")
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

  @Step("Check first page buttons")
  public PaginationStep checkFirstPageButtonsState() {
    checkAllNumberedButtonsIsEnabled();
    isEnabled(NEXT_PAGE_BUTTON);
    isDisabled(PREV_PAGE_BUTTON);
    isEnabled(LAST_PAGE_BUTTON);
    return this;
  }

  @Step("Check middle page buttons")
  public PaginationStep checkMiddlePageButtonsState() {
    checkAllNumberedButtonsIsEnabled();
    isEnabled(NEXT_PAGE_BUTTON);
    isEnabled(PREV_PAGE_BUTTON);
    isEnabled(LAST_PAGE_BUTTON);
    return this;
  }

  @Step("Check last page buttons")
  public PaginationStep checkLastPageButtonsState() {
    checkAllNumberedButtonsIsEnabled();
    isDisabled(NEXT_PAGE_BUTTON);
    isEnabled(PREV_PAGE_BUTTON);
    isDisabled(LAST_PAGE_BUTTON);
    return this;
  }

  @Step("Check pagination on '{pageNum}' page")
  public PaginationStep checkPagination(int pageNum, PaginationElement.PageSize pageSize, TableColumn tableColumn,
                                        List<String> testColumnValues) {
    checkNumberedButtonIsSelected(pageNum)
        .checkNumberedButtonsAmount(getNumberedButtonsQuantity(testColumnValues.size(), pageSize.getSize()))
        .checkShowPerPageValue(pageSize);
    tableStep.checkColumnValues(tableColumn, getExpectedValues(testColumnValues, pageNum, pageSize.getSize()));
    return this;
  }

  @Step("Check pagination table of the page")
  public void checkPaginationFixture(TableColumn tableColumn, List<String> testColumnValues) {
    // testColumnValues must be ordered as UI shown
    assertThat("testColumnValues size must be 101", testColumnValues.size(), is(101));

    waitVisibility(getNumberedButtonByPageNum(11));
    checkPagination(1, TEN, tableColumn, testColumnValues)
        .checkFirstPageButtonsState();

    waitAndClick(NEXT_PAGE_BUTTON);
    checkPagination(2, TEN, tableColumn, testColumnValues)
        .checkMiddlePageButtonsState();

    waitAndClick(PREV_PAGE_BUTTON);
    checkPagination(1, TEN, tableColumn, testColumnValues);

    waitAndClick(LAST_PAGE_BUTTON);
    checkPagination(11, TEN, tableColumn, testColumnValues)
        .checkLastPageButtonsState();

    waitAndClick(EXTEND_PAGES_BUTTON);
    checkPagination(6, TEN, tableColumn, testColumnValues);

    waitAndClick(getNumberedButtonByPageNum(4));
    checkPagination(4, TEN, tableColumn, testColumnValues);

    setShowPerPageOption(THIRTY)
        .checkPagination(1, THIRTY, tableColumn, testColumnValues);
    setShowPerPageOption(FIFTY)
        .checkPagination(1, FIFTY, tableColumn, testColumnValues);
    setShowPerPageOption(HUNDRED)
        .checkPagination(1, HUNDRED, tableColumn, testColumnValues);
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

  private int getNumberedButtonsQuantity(int testColumnValuesSize, int pageSize) {
    int pages = (testColumnValuesSize + pageSize - 1) / pageSize;
    return Math.min(pages, 9);
  }
}
