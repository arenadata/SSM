/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
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
import org.springframework.stereotype.Service;

import static com.codeborne.selenide.CollectionCondition.allMatch;
import static com.codeborne.selenide.Condition.exactText;
import static com.codeborne.selenide.Condition.exactValue;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.smartdata.test.element.PaginationElement.EXTEND_PAGES_BUTTON;
import static org.smartdata.test.element.PaginationElement.LAST_PAGE_BUTTON;
import static org.smartdata.test.element.PaginationElement.NEXT_PAGE_BUTTON;
import static org.smartdata.test.element.PaginationElement.PAGINATION_NUMBERED_BUTTONS;
import static org.smartdata.test.element.PaginationElement.PAGINATION_PER_PAGE_OPTION;
import static org.smartdata.test.element.PaginationElement.PREV_PAGE_BUTTON;
import static org.smartdata.test.element.PaginationElement.SHOW_PER_PAGE_OPTIONS;
import static org.smartdata.test.element.PaginationElement.SHOW_PER_PAGE_SELECT;
import static org.smartdata.test.element.PaginationElement.getNumberedButtonByPageNum;

@Slf4j
@Service
public class PaginationStep extends BaseWebStep {

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
    PAGINATION_PER_PAGE_OPTION.shouldHave(exactValue(pageSize.getOptionName()));
    return this;
  }

  @Step("Set 'Show per page' value")
  public PaginationStep setShowPerPageOption(PaginationElement.PageSize pageSize) {
    waitAndClick(SHOW_PER_PAGE_SELECT);
    waitAndClick(SHOW_PER_PAGE_OPTIONS.find(exactText(pageSize.getOptionName())));
    return this;
  }
}
