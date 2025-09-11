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

import io.arenadata.test.step.BaseWebStep;
import io.qameta.allure.Step;
import lombok.extern.slf4j.Slf4j;
import org.smartdata.test.model.SortOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import static org.smartdata.test.element.HottestFilesPageElement.ClusterInfoHottestFilesTableColumn.ACCESS_COUNT;
import static org.smartdata.test.element.HottestFilesPageElement.ClusterInfoHottestFilesTableColumn.FILE_PATH;
import static org.smartdata.test.element.HottestFilesPageElement.ClusterInfoHottestFilesTableColumn.ID;
import static org.smartdata.test.element.HottestFilesPageElement.HOTTEST_FILES_RESET_FILTER_BUTTON;
import static org.smartdata.test.element.TableElement.TableType.SECONDARY;

@Slf4j
@Service
public class HottestFilesStep extends BaseWebStep {

  @Autowired
  private TableStep tableStep;

  @Autowired
  TableFilterPopupStep tableFilterPopupStep;

  @Step("Check 'Hottest files' sorting")
  public HottestFilesStep checkSorting() {
    tableStep.checkSelectedSorting(SECONDARY, ACCESS_COUNT, SortOrder.ASC)
        .checkColumnValuesIsSorted(SECONDARY, ACCESS_COUNT, SortOrder.ASC)
        .checkSorting(SECONDARY, ID)
        .checkSorting(SECONDARY, FILE_PATH)
        .checkSorting(SECONDARY, ACCESS_COUNT);
    return this;
  }

  @Step("Check filtration by 'File path'")
  public HottestFilesStep checkFilePathFiltration() {
    tableStep.clickFilterButton(SECONDARY, FILE_PATH);
    tableFilterPopupStep.setTextPopupInput("file2");
    tableStep.checkTableRowsCountIs(SECONDARY, 1)
        .checkColumnValueInFirstRow(SECONDARY, FILE_PATH, "file2.txt");
    waitAndClick(HOTTEST_FILES_RESET_FILTER_BUTTON);
    tableStep.checkTableRowsCountIs(SECONDARY, 2);
    return this;
  }
}
