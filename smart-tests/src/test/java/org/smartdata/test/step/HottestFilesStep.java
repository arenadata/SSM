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

import java.util.List;

import static org.smartdata.test.element.HottestFilesPageElement.ClusterInfoHottestFilesTableColumn.ACCESS_COUNT;
import static org.smartdata.test.element.HottestFilesPageElement.ClusterInfoHottestFilesTableColumn.FILE_PATH;
import static org.smartdata.test.element.HottestFilesPageElement.ClusterInfoHottestFilesTableColumn.ID;
import static org.smartdata.test.element.TableElement.TableType.HOTTEST_FILES;
import static org.smartdata.test.model.SortOrder.ASC;

@Slf4j
@Service
public class HottestFilesStep extends BaseWebStep {

  @Autowired
  private TableStep tableStep;

  @Autowired
  private TableFilterPopupStep tableFilterPopupStep;

  @Autowired
  private PaginationStep paginationStep;

  @Step("Check 'Hottest files' sorting")
  public HottestFilesStep checkSorting() {
    tableStep.checkSelectedSorting(HOTTEST_FILES, ACCESS_COUNT, ASC)
        .checkColumnValuesIsSorted(HOTTEST_FILES, ACCESS_COUNT, ASC)
        .checkSorting(HOTTEST_FILES, ID)
        .checkSorting(HOTTEST_FILES, FILE_PATH)
        .checkSorting(HOTTEST_FILES, ACCESS_COUNT);
    return this;
  }

  @Step("Check filtration by 'File path'")
  public HottestFilesStep checkFilePathFiltration() {
    tableStep.clickFilterButton(HOTTEST_FILES, FILE_PATH);
    tableFilterPopupStep.setTextPopupInput("file2");
    tableStep.checkTableRowsCountIs(HOTTEST_FILES, 1)
        .checkColumnValueInFirstRow(HOTTEST_FILES, FILE_PATH, "file2.txt")
        .clickResetFilterButton(HOTTEST_FILES.getTableElement())
        .checkTableRowsCountIs(HOTTEST_FILES, 2);
    return this;
  }

  @Step("Check 'Hottest files' pagination")
  public HottestFilesStep checkPagination(List<String> expectedFilePathList) {
    tableStep.clickOnSortingColumn(HOTTEST_FILES, ID);
    paginationStep.checkPaginationFixture(HOTTEST_FILES,
        FILE_PATH,
        expectedFilePathList,
        HOTTEST_FILES.getTableElement());
    return this;
  }
}
