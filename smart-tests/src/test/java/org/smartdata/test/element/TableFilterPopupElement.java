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
  SelenideElement TEXT_FILTER_INPUT = $x("//*[contains(@class, 'tableSearchFilter')]//input");
  SelenideElement DATA_PICKER_APPLY_BUTTON = $x("//*[@data-test='data-picker-panel']//button[.='Apply']");
  SelenideElement DATA_PICKER_CALENDAR_TAB_BUTTON = $x("//*[@data-test='data-picker-panel']//button[.='Calendar']");
  String MULTISELECT_CHECKBOX_XPATH =
      "//div[@data-test='options-container']//label[span[text()='%s']]/input[@type='checkbox']";
  String DATA_PICKER_CALENDAR_INPUT_TEMPLATE_XPATH = "//div[div/label[text()='%s']]//input[@data-input-id='%s']";
  String DATA_PICKER_RANGE_INPUT_TEMPLATE_XPATH = "//div[div/label[text()='%s']]//input";

  static SelenideElement getDatePickerCalendarInput(String inputName, String timeUnitName) {
    return $x(format(DATA_PICKER_CALENDAR_INPUT_TEMPLATE_XPATH, inputName, timeUnitName));
  }

  static SelenideElement getDatePickerRangeInput(String inputName) {
    return $x(format(DATA_PICKER_RANGE_INPUT_TEMPLATE_XPATH, inputName));
  }

  static SelenideElement getMultiselectCheckbox(String value) {
    return $x(format(MULTISELECT_CHECKBOX_XPATH, value));
  }
}
