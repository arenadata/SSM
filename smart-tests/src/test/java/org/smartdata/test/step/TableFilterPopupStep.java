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

import io.arenadata.test.step.BaseWebStep;
import io.qameta.allure.Step;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

import static com.codeborne.selenide.Condition.exactValue;
import static io.arenadata.test.util.constant.TimeoutConstants.DEFAULT_WEB_ELEMENT_TIMEOUT;
import static org.smartdata.test.element.TableFilterPopupElement.DATA_PICKER_APPLY_BUTTON;
import static org.smartdata.test.element.TableFilterPopupElement.DATA_PICKER_CALENDAR_TAB_BUTTON;
import static org.smartdata.test.element.TableFilterPopupElement.TEXT_FILTER_INPUT;
import static org.smartdata.test.element.TableFilterPopupElement.getDatePickerCalendarInput;
import static org.smartdata.test.element.TableFilterPopupElement.getDatePickerRangeInput;
import static org.smartdata.test.element.TableFilterPopupElement.getMultiselectCheckbox;

@Slf4j
@Service
public class TableFilterPopupStep extends BaseWebStep {
  private static final String FROM_TIME_INPUT_LABEL = "from";
  private static final String TO_TIME_INPUT_LABEL = "to";
  private static final String DAY_TIME_UNIT_NAME = "day";
  private static final String MONTH_TIME_UNIT_NAME = "month";
  private static final String YEAR_TIME_UNIT_NAME = "year";
  private static final String HOURS_TIME_UNIT_NAME = "hours";
  private static final String MINUTES_TIME_UNIT_NAME = "minutes";
  private static final String SECONDS_TIME_UNIT_NAME = "seconds";

  @Step("Enter '{value}' in the text filter input field of the popup")
  public TableFilterPopupStep setTextPopupInput(String value) {
    waitAndReWrite(TEXT_FILTER_INPUT, value);
    return this;
  }

  @Step("Click 'Apply' button in the data picker popup")
  public TableFilterPopupStep clickOnDataPickerApplyButton() {
    waitAndClick(DATA_PICKER_APPLY_BUTTON);
    return this;
  }

  @Step("Click 'Calendar' tab in the data picker popup")
  public TableFilterPopupStep clickOnCalendarTabButton() {
    waitAndClick(DATA_PICKER_CALENDAR_TAB_BUTTON);
    return this;
  }

  @Step("Check range values in the data picker popup")
  public TableFilterPopupStep checkDataPickerRangeValues(String from, String to) {
    getDatePickerRangeInput(FROM_TIME_INPUT_LABEL).shouldHave(exactValue(from), DEFAULT_WEB_ELEMENT_TIMEOUT);
    getDatePickerRangeInput(TO_TIME_INPUT_LABEL).shouldHave(exactValue(to), DEFAULT_WEB_ELEMENT_TIMEOUT);
    return this;
  }

  @Step("Click '{value}' checkbox in the multiselect popup")
  public TableFilterPopupStep clickMultiselectPopupCheckbox(String value) {
    waitAndClick(getMultiselectCheckbox(value));
    return this;
  }

  @Step("Set date and time in calendar: from '{from}' to '{to}'")
  public TableFilterPopupStep setDataPickerCalendarValues(LocalDateTime from, LocalDateTime to) {
    setDatePickerCalendarValue(FROM_TIME_INPUT_LABEL, from);
    setDatePickerCalendarValue(TO_TIME_INPUT_LABEL, to);
    return this;
  }

  @Step("Set date and time in the '{inputName}' input to '{startDateTime}'")
  private void setDatePickerCalendarValue(String inputName, LocalDateTime startDateTime) {
    waitAndReWrite(getDatePickerCalendarInput(inputName, YEAR_TIME_UNIT_NAME),
        String.valueOf(startDateTime.getYear()));
    waitAndReWrite(getDatePickerCalendarInput(inputName, MONTH_TIME_UNIT_NAME),
        String.valueOf(startDateTime.getMonthValue()));
    waitAndReWrite(getDatePickerCalendarInput(inputName, DAY_TIME_UNIT_NAME),
        String.valueOf(startDateTime.getDayOfMonth()));
    waitAndReWrite(getDatePickerCalendarInput(inputName, HOURS_TIME_UNIT_NAME),
        String.valueOf(startDateTime.getHour()));
    waitAndReWrite(getDatePickerCalendarInput(inputName, MINUTES_TIME_UNIT_NAME),
        String.valueOf(startDateTime.getMinute()));
    waitAndReWrite(getDatePickerCalendarInput(inputName, SECONDS_TIME_UNIT_NAME),
        String.valueOf(startDateTime.getSecond()));
  }
}
