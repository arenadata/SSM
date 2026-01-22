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
import static java.lang.String.format;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.smartdata.test.element.PaginationElement.PageSize.FIFTY;
import static org.smartdata.test.element.PaginationElement.PageSize.HUNDRED;
import static org.smartdata.test.element.PaginationElement.PageSize.TEN;
import static org.smartdata.test.element.PaginationElement.PageSize.THIRTY;
import static org.smartdata.test.element.PaginationElement.SHOW_PER_PAGE_OPTIONS;
import static org.smartdata.test.element.PaginationElement.getExtendPageButton;
import static org.smartdata.test.element.PaginationElement.getLastPageButton;
import static org.smartdata.test.element.PaginationElement.getNextPageButton;
import static org.smartdata.test.element.PaginationElement.getNumberedButtonByPageNum;
import static org.smartdata.test.element.PaginationElement.getNumberedButtons;
import static org.smartdata.test.element.PaginationElement.getPerPageInput;
import static org.smartdata.test.element.PaginationElement.getPreviousPageButton;
import static org.smartdata.test.element.TableElement.TableType;
import static org.smartdata.test.element.TableElement.TableType.PRIMARY;
import static org.smartdata.test.util.constant.CommonConstants.PAGINATION_QUANTITY;

@Slf4j
@Service
public class PaginationStep extends BaseWebStep {

  @Autowired
  private TableStep tableStep;

  @Step("Check {pageNum} page button is selected")
  public PaginationStep checkNumberedButtonIsSelected(int pageNum, SelenideElement baseElement) {
    SelenideElement numberedButton = getNumberedButtonByPageNum(pageNum, baseElement);
    waitVisibility(numberedButton);
    numberedButton.should(attributeMatching("class", ".*is-active.*"));
    return this;
  }

  @Step("Check all page buttons are visible and enabled")
  public PaginationStep checkAllNumberedButtonsIsEnabled(SelenideElement baseElement) {
    getNumberedButtons(baseElement).should(allMatch("All numbered buttons should be visible", WebElement::isDisplayed));
    getNumberedButtons(baseElement).should(allMatch("All numbered buttons should be enabled", WebElement::isEnabled));
    return this;
  }

  @Step("Check that there are {expectedAmount} numbered pagination buttons on the page")
  public PaginationStep checkNumberedButtonsAmount(int expectedAmount, SelenideElement baseElement) {
    checkSize(getNumberedButtons(baseElement), expectedAmount);
    return this;
  }

  @Step("Check selected 'Show per page' value")
  public PaginationStep checkShowPerPageValue(PaginationElement.PageSize pageSize, SelenideElement baseElement) {
    getPerPageInput(baseElement).shouldHave(exactValue(pageSize.getOptionName()));
    return this;
  }

  @Step("Set 'Show per page' value")
  public PaginationStep setShowPerPageOption(PaginationElement.PageSize pageSize, SelenideElement baseElement) {
    waitAndClick(getPerPageInput(baseElement));
    waitAndClick(SHOW_PER_PAGE_OPTIONS.find(exactText(pageSize.getOptionName())));
    return this;
  }

  @Step("Check first page buttons")
  public PaginationStep checkFirstPageButtonsState(SelenideElement baseElement) {
    checkAllNumberedButtonsIsEnabled(baseElement);
    isEnabled(getNextPageButton(baseElement));
    isDisabled(getPreviousPageButton(baseElement));
    isEnabled(getLastPageButton(baseElement));
    return this;
  }

  @Step("Check middle page buttons")
  public PaginationStep checkMiddlePageButtonsState(SelenideElement baseElement) {
    checkAllNumberedButtonsIsEnabled(baseElement);
    isEnabled(getNextPageButton(baseElement));
    isEnabled(getPreviousPageButton(baseElement));
    isEnabled(getLastPageButton(baseElement));
    return this;
  }

  @Step("Check last page buttons")
  public PaginationStep checkLastPageButtonsState(SelenideElement baseElement) {
    checkAllNumberedButtonsIsEnabled(baseElement);
    isDisabled(getNextPageButton(baseElement));
    isEnabled(getPreviousPageButton(baseElement));
    isDisabled(getLastPageButton(baseElement));
    return this;
  }

  @Step("Check pagination on '{pageNum}' page")
  public PaginationStep checkPagination(int pageNum, PaginationElement.PageSize pageSize,
                                        TableType tableType, TableColumn tableColumn,
                                        List<String> testColumnValues, SelenideElement baseElement) {
    checkNumberedButtonIsSelected(pageNum, baseElement)
        .checkNumberedButtonsAmount(getNumberedButtonsQuantity(testColumnValues.size(), pageSize.getSize()),
            baseElement)
        .checkShowPerPageValue(pageSize, baseElement);
    tableStep.checkColumnValues(tableType, tableColumn,
        getExpectedValues(testColumnValues, pageNum, pageSize.getSize()));
    return this;
  }

  @Step("Check pagination table of the page")
  public void checkPaginationFixture(TableColumn tableColumn, List<String> testColumnValues) {
    checkPaginationFixture(PRIMARY, tableColumn, testColumnValues, null);
  }

  @Step("Check pagination table of the page")
  public void checkPaginationFixture(TableType tableType, TableColumn tableColumn, List<String> testColumnValues,
                                     SelenideElement baseElement) {
    // testColumnValues must be ordered as UI shown
    assertThat(format("testColumnValues size must be %s", PAGINATION_QUANTITY),
        testColumnValues.size(), is(PAGINATION_QUANTITY));

    waitVisibility(getNumberedButtonByPageNum(11, baseElement));
    checkPagination(1, TEN, tableType, tableColumn, testColumnValues, baseElement)
        .checkFirstPageButtonsState(baseElement);

    waitAndClick(getNextPageButton(baseElement));
    checkPagination(2, TEN, tableType, tableColumn, testColumnValues, baseElement)
        .checkMiddlePageButtonsState(baseElement);

    waitAndClick(getPreviousPageButton(baseElement));
    checkPagination(1, TEN, tableType, tableColumn, testColumnValues, baseElement);

    waitAndClick(getLastPageButton(baseElement));
    checkPagination(11, TEN, tableType, tableColumn, testColumnValues, baseElement)
        .checkLastPageButtonsState(baseElement);

    waitAndClick(getExtendPageButton(baseElement));
    checkPagination(6, TEN, tableType, tableColumn, testColumnValues, baseElement);

    waitAndClick(getNumberedButtonByPageNum(4, baseElement));
    checkPagination(4, TEN, tableType, tableColumn, testColumnValues, baseElement);

    setShowPerPageOption(THIRTY, baseElement)
        .checkPagination(1, THIRTY, tableType, tableColumn, testColumnValues, baseElement);
    setShowPerPageOption(FIFTY, baseElement)
        .checkPagination(1, FIFTY, tableType, tableColumn, testColumnValues, baseElement);
    setShowPerPageOption(HUNDRED, baseElement)
        .checkPagination(1, HUNDRED, tableType, tableColumn, testColumnValues, baseElement);
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
    return Math.min(pages, 8);
  }
}
