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
import static com.codeborne.selenide.Selenide.$x;

public interface PaginationElement {
  SelenideElement PAGINATION_PER_PAGE_INPUT =
      $x("//*[contains(@class, 'pagination') and contains(@class, 'commonSelectField')]//input");
  ElementsCollection PAGINATION_NUMBERED_BUTTONS =
      $$x("//*[contains(@class, 'paginationButton') and not(contains(@class, 'Arrow'))]");
  SelenideElement NEXT_PAGE_BUTTON = $x("//*[@data-test='pagination-next-page']");
  SelenideElement PREV_PAGE_BUTTON = $x("//*[@data-test='pagination-prev-page']");
  SelenideElement LAST_PAGE_BUTTON = $x("//*[@data-test='pagination-last-page']");
  SelenideElement EXTEND_PAGES_BUTTON = $x("//*[contains(@class, 'paginationButton') and .='...']");
  SelenideElement SHOW_PER_PAGE_SELECT = $x("//*[contains(@class,'pagination__select')]//input");
  ElementsCollection SHOW_PER_PAGE_OPTIONS = $$x("//*[@data-test='pagination-per-page-popover']//li");

  static SelenideElement getNumberedButtonByPageNum(String pageNum) {
    return PAGINATION_NUMBERED_BUTTONS.find(exactText(pageNum));
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
