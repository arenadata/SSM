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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

import static java.time.ZoneOffset.UTC;
import static org.smartdata.test.element.AuditPageElement.AuditTableColumn.DATE;
import static org.smartdata.test.element.AuditPageElement.AuditTableColumn.OBJECT_TYPE;
import static org.smartdata.test.element.AuditPageElement.AuditTableColumn.OPERATION;
import static org.smartdata.test.element.AuditPageElement.AuditTableColumn.RESULT;
import static org.smartdata.test.element.AuditPageElement.AuditTableColumn.USER;
import static org.smartdata.test.model.AuditStatus.FAILURE;


@Slf4j
@Service
public class AuditStep extends BaseWebStep {

  @Autowired
  private TableStep tableStep;

  @Autowired
  private TableFilterPopupStep tableFilterPopupStep;

  @Step("Check filtration by 'User'")
  public AuditStep checkAuditUserFiltration() {
    tableStep.clickFilterButton(USER);
    tableFilterPopupStep.setTextPopupInput("fake");
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(USER, "fakeUser")
        .clickResetFilterButton()
        .checkTableRowsCountIs(2);
    return this;
  }

  @Step("Check filtration by 'Date'")
  public AuditStep checkAuditDateFiltration() {
    tableStep.clickFilterButton(DATE);
    tableFilterPopupStep.checkDataPickerRangeValues("now-1h", "now")
        .clickOnDataPickerApplyButton();
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(USER, "john")
        .clickResetFilterButton()
        .checkTableRowsCountIs(2)
        .clickFilterButton(DATE);
    tableFilterPopupStep.clickOnCalendarTabButton()
        .setDataPickerCalendarValues(LocalDateTime.now(UTC).minusHours(1), LocalDateTime.now(UTC))
        .clickOnDataPickerApplyButton();
    tableStep.checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(USER, "john")
        .clickResetFilterButton()
        .checkTableRowsCountIs(2);
    return this;
  }

  @Step("Check filtration by 'Object Type'")
  public AuditStep checkAuditObjectTypeFiltration() {
    tableStep.clickFilterButton(OBJECT_TYPE);
    tableFilterPopupStep.clickMultiselectPopupCheckbox("Cmdlet");
    tableStep.clickFilterButton(OBJECT_TYPE)
        .checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(USER, "john")
        .clickResetFilterButton()
        .checkTableRowsCountIs(2);
    return this;
  }

  @Step("Check filtration by 'Operation'")
  public AuditStep checkAuditOperationFiltration() {
    tableStep.clickFilterButton(OPERATION);
    tableFilterPopupStep.clickMultiselectPopupCheckbox("Create");
    tableStep.clickFilterButton(OPERATION)
        .checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(USER, "fakeUser")
        .clickResetFilterButton()
        .checkTableRowsCountIs(2);
    return this;
  }

  @Step("Check filtration by 'Result'")
  public AuditStep checkAuditResultFiltration() {
    tableStep.clickFilterButton(RESULT);
    tableFilterPopupStep.clickMultiselectPopupCheckbox(FAILURE.getText());
    tableStep.clickFilterButton(RESULT)
        .checkTableRowsCountIs(1)
        .checkColumnValueInFirstRow(USER, "john")
        .clickResetFilterButton()
        .checkTableRowsCountIs(2);
    return this;
  }
}
