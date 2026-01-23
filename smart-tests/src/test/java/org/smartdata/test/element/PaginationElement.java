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
package org.smartdata.test.element;

import com.codeborne.selenide.ElementsCollection;
import com.codeborne.selenide.SelenideElement;
import lombok.Getter;

import static com.codeborne.selenide.Condition.exactText;
import static com.codeborne.selenide.Selenide.$$x;
import static org.smartdata.test.util.WebElementUtil.findAllFromBaseElement;
import static org.smartdata.test.util.WebElementUtil.findFromBaseElement;

public interface PaginationElement {
  String PAGINATION_NUMBERED_BUTTONS = ".//*[@data-qa='page-number']";
  String NEXT_PAGE_BUTTON = ".//*[@data-qa='pagination-next-page']";
  String PREV_PAGE_BUTTON = ".//*[@data-qa='pagination-prev-page']";
  String LAST_PAGE_BUTTON = ".//*[@data-qa='pagination-last-page']";
  String EXTEND_PAGES_BUTTON = ".//*[contains(@class, 'paginationButton') and .='...']";
  String SHOW_PER_PAGE_INPUT = ".//*[contains(@class, 'pagination') and contains(@class, 'commonSelectField')]//input";
  ElementsCollection SHOW_PER_PAGE_OPTIONS = $$x(".//*[@data-qa='pagination-per-page-popover']//li");

  static SelenideElement getNumberedButtonByPageNum(int pageNum, SelenideElement baseElement) {
    return getNumberedButtons(baseElement).find(exactText(String.valueOf(pageNum)));
  }

  static ElementsCollection getNumberedButtons(SelenideElement baseElement) {
    return findAllFromBaseElement(baseElement, PAGINATION_NUMBERED_BUTTONS);
  }

  static SelenideElement getPerPageInput(SelenideElement baseElement) {
    return findFromBaseElement(baseElement, SHOW_PER_PAGE_INPUT);
  }

  static SelenideElement getNextPageButton(SelenideElement baseElement) {
    return findFromBaseElement(baseElement, NEXT_PAGE_BUTTON);
  }

  static SelenideElement getPreviousPageButton(SelenideElement baseElement) {
    return findFromBaseElement(baseElement, PREV_PAGE_BUTTON);
  }

  static SelenideElement getLastPageButton(SelenideElement baseElement) {
    return findFromBaseElement(baseElement, LAST_PAGE_BUTTON);
  }

  static SelenideElement getExtendPageButton(SelenideElement baseElement) {
    return findFromBaseElement(baseElement, EXTEND_PAGES_BUTTON);
  }

  @Getter
  enum PageSize {
    TEN(10),
    THIRTY(30),
    FIFTY(50),
    HUNDRED(100);

    private final int size;
    private final String optionName;

    PageSize(int size) {
      this.size = size;
      this.optionName = String.format("%d per page", size);
    }
  }
}
