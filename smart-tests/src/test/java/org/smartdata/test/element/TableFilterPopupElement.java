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

import com.codeborne.selenide.SelenideElement;

import static com.codeborne.selenide.Selenide.$x;
import static java.lang.String.format;

public interface TableFilterPopupElement {
  SelenideElement DATA_PICKER_PANEL = $x("//*[@data-test='data-picker-panel']");
  SelenideElement TEXT_FILTER_INPUT = $x("//*[contains(@class, 'tableSearchFilter')]//input");
  SelenideElement DATA_PICKER_APPLY_BUTTON = DATA_PICKER_PANEL.$x(".//button[.='Apply']");
  SelenideElement DATA_PICKER_CALENDAR_TAB_BUTTON = DATA_PICKER_PANEL.$x(".//button[.='Calendar']");
  String MULTISELECT_CHECKBOX_XPATH = "//*[@data-test='options-container']//label[.='%s']//input[@type='checkbox']";
  String DATA_PICKER_RANGE_INPUT_TEMPLATE_XPATH = ".//*[contains(@class, 'formField') and .//label='%s']//input";
  String DATA_PICKER_CALENDAR_INPUT_TEMPLATE_XPATH =
      ".//*[contains(@class, 'formField') and .//label='%s']//input[@data-input-id='%s']";

  static SelenideElement getDatePickerCalendarInput(String inputName, String timeUnitName) {
    return DATA_PICKER_PANEL.$x(format(DATA_PICKER_CALENDAR_INPUT_TEMPLATE_XPATH, inputName, timeUnitName));
  }

  static SelenideElement getDatePickerRangeInput(String inputName) {
    return DATA_PICKER_PANEL.$x(format(DATA_PICKER_RANGE_INPUT_TEMPLATE_XPATH, inputName));
  }

  static SelenideElement getMultiselectCheckbox(String value) {
    return $x(format(MULTISELECT_CHECKBOX_XPATH, value));
  }
}
