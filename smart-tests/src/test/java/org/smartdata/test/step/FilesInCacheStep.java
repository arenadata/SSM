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
import org.smartdata.test.util.comparator.UiDateTimeComparator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

import static java.time.ZoneOffset.UTC;
import static org.smartdata.test.element.FilesInCachePageElement.ClusterInfoFilesInCacheTableColumn.ACCESS_COUNT;
import static org.smartdata.test.element.FilesInCachePageElement.ClusterInfoFilesInCacheTableColumn.CACHED_TIME;
import static org.smartdata.test.element.FilesInCachePageElement.ClusterInfoFilesInCacheTableColumn.FILE_PATH;
import static org.smartdata.test.element.FilesInCachePageElement.ClusterInfoFilesInCacheTableColumn.ID;
import static org.smartdata.test.element.FilesInCachePageElement.ClusterInfoFilesInCacheTableColumn.LAST_ACCESSED_TIME;
import static org.smartdata.test.element.TableElement.TableType.FILES_IN_CACHE;
import static org.smartdata.test.model.SortOrder.ASC;

@Slf4j
@Service
public class FilesInCacheStep extends BaseWebStep {

  @Autowired
  private TableStep tableStep;

  @Autowired
  private TableFilterPopupStep tableFilterPopupStep;

  @Autowired
  private PaginationStep paginationStep;

  @Step("Check 'Files in cache' sorting")
  public FilesInCacheStep checkSorting() {
    tableStep.checkSelectedSorting(FILES_IN_CACHE, ACCESS_COUNT, ASC)
        .checkColumnValuesIsSorted(FILES_IN_CACHE, ACCESS_COUNT, ASC)
        .checkSorting(FILES_IN_CACHE, ID)
        .checkSorting(FILES_IN_CACHE, FILE_PATH)
        .checkSorting(FILES_IN_CACHE, CACHED_TIME, new UiDateTimeComparator())
        .checkSorting(FILES_IN_CACHE, LAST_ACCESSED_TIME, new UiDateTimeComparator())
        .checkSorting(FILES_IN_CACHE, ACCESS_COUNT);
    return this;
  }

  @Step("Check 'Files in cache' pagination")
  public FilesInCacheStep checkPagination(List<String> expectedFileIdList) {
    tableStep.clickOnSortingColumn(FILES_IN_CACHE, ID);
    paginationStep.checkPaginationFixture(FILES_IN_CACHE, ID, expectedFileIdList, FILES_IN_CACHE.getTableElement());
    return this;
  }

  @Step("Check 'File path' filtration")
  public FilesInCacheStep checkFilePathFiltration() {
    tableStep.clickFilterButton(FILES_IN_CACHE, FILE_PATH);
    tableFilterPopupStep.setTextPopupInput("file2");
    tableStep.checkTableRowsCountIs(FILES_IN_CACHE, 1)
        .checkColumnValueInFirstRow(FILES_IN_CACHE, FILE_PATH, "/file2.txt")
        .clickResetFilterButton(FILES_IN_CACHE.getTableElement())
        .checkTableRowsCountIs(FILES_IN_CACHE, 2);
    return this;
  }

  @Step("Check 'Cached Time' filtration")
  public FilesInCacheStep checkCachedTimeFiltration() {
    tableStep.clickFilterButton(FILES_IN_CACHE, CACHED_TIME);
    tableFilterPopupStep.checkDataPickerRangeValues("now-1h", "now")
        .clickOnDataPickerApplyButton();
    tableStep.checkTableRowsCountIs(FILES_IN_CACHE, 1)
        .checkColumnValueInFirstRow(FILES_IN_CACHE, FILE_PATH, "/file1.txt")
        .clickResetFilterButton(FILES_IN_CACHE.getTableElement())
        .checkTableRowsCountIs(FILES_IN_CACHE, 2)
        .clickFilterButton(FILES_IN_CACHE, CACHED_TIME);
    tableFilterPopupStep.clickOnCalendarTabButton()
        .setDataPickerCalendarValues(LocalDateTime.now(UTC).minusHours(1), LocalDateTime.now(UTC))
        .clickOnDataPickerApplyButton();
    tableStep.checkTableRowsCountIs(FILES_IN_CACHE, 1)
        .checkColumnValueInFirstRow(FILES_IN_CACHE, FILE_PATH, "/file1.txt")
        .clickResetFilterButton(FILES_IN_CACHE.getTableElement())
        .checkTableRowsCountIs(FILES_IN_CACHE, 2);
    return this;
  }

  @Step("Check 'Last Accessed Time' filtration")
  public FilesInCacheStep checkLastAccessedTimeFiltration() {
    tableStep.clickFilterButton(FILES_IN_CACHE, LAST_ACCESSED_TIME);
    tableFilterPopupStep.checkDataPickerRangeValues("now-1h", "now")
        .clickOnDataPickerApplyButton();
    tableStep.checkTableRowsCountIs(FILES_IN_CACHE, 1)
        .checkColumnValueInFirstRow(FILES_IN_CACHE, FILE_PATH, "/file1.txt")
        .clickResetFilterButton(FILES_IN_CACHE.getTableElement())
        .checkTableRowsCountIs(FILES_IN_CACHE, 2)
        .clickFilterButton(FILES_IN_CACHE, LAST_ACCESSED_TIME);
    tableFilterPopupStep.clickOnCalendarTabButton()
        .setDataPickerCalendarValues(LocalDateTime.now(UTC).minusHours(1), LocalDateTime.now(UTC))
        .clickOnDataPickerApplyButton();
    tableStep.checkTableRowsCountIs(FILES_IN_CACHE, 1)
        .checkColumnValueInFirstRow(FILES_IN_CACHE, FILE_PATH, "/file1.txt")
        .clickResetFilterButton(FILES_IN_CACHE.getTableElement())
        .checkTableRowsCountIs(FILES_IN_CACHE, 2);
    return this;
  }
}
