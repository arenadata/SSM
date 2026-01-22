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

import static com.codeborne.selenide.Condition.attributeMatching;
import static io.arenadata.test.util.constant.TimeoutConstants.DEFAULT_WEB_ELEMENT_TIMEOUT;
import static java.time.ZoneOffset.UTC;
import static org.smartdata.test.element.ClusterInfoPageElement.ClusterInfoTableColumn.REGISTER_TIME;
import static org.smartdata.test.element.ClusterInfoPageElement.FILES_IN_CACHE_TAB;


@Slf4j
@Service
public class ClusterInfoStep extends BaseWebStep {

  @Autowired
  private TableStep tableStep;

  @Autowired
  private TableFilterPopupStep tableFilterPopupStep;

  @Step("Check filtration by 'Register Time'")
  public ClusterInfoStep checkClusterInfoRegisterTimeFiltration() {
    tableStep.clickFilterButton(REGISTER_TIME);
    tableFilterPopupStep.checkDataPickerRangeValues("now-1h", "now")
        .clickOnDataPickerApplyButton();
    tableStep.checkTableRowsCountIs(2)
        .clickResetFilterButton()
        .checkTableRowsCountIs(2)
        .openFilterPanel(REGISTER_TIME);
    tableFilterPopupStep.clickOnCalendarTabButton()
        .setDataPickerCalendarValues(LocalDateTime.now(UTC).minusDays(2), LocalDateTime.now(UTC).minusDays(1))
        .clickOnDataPickerApplyButton();
    tableStep.checkTableRowsCountIs(0)
        .clickResetFilterButton()
        .checkTableRowsCountIs(2);
    return this;
  }

  @Step("Open 'Files in cache' tab")
  public ClusterInfoStep openFilesInCacheTab() {
    waitAndClick(FILES_IN_CACHE_TAB);
    FILES_IN_CACHE_TAB.should(attributeMatching("class", ".*active.*"), DEFAULT_WEB_ELEMENT_TIMEOUT);
    return this;
  }
}
