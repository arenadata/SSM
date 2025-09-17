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

import static org.smartdata.test.element.FilesInCachePageElement.ClusterInfoFilesInCachTableColumn.ACCESS_COUNT;
import static org.smartdata.test.element.FilesInCachePageElement.ClusterInfoFilesInCachTableColumn.CACHED_TIME;
import static org.smartdata.test.element.FilesInCachePageElement.ClusterInfoFilesInCachTableColumn.FILE_PATH;
import static org.smartdata.test.element.FilesInCachePageElement.ClusterInfoFilesInCachTableColumn.ID;
import static org.smartdata.test.element.FilesInCachePageElement.ClusterInfoFilesInCachTableColumn.LAST_ACCESSED_TIME;
import static org.smartdata.test.element.FilesInCachePageElement.FILES_IN_CACHE_TOOLBAR;
import static org.smartdata.test.element.TableElement.TableType.SECONDARY;
import static org.smartdata.test.model.SortOrder.ASC;

@Slf4j
@Service
public class FilesInCacheStep extends BaseWebStep {

  @Autowired
  private TableStep tableStep;

  @Autowired
  private PaginationStep paginationStep;

  @Step("Check 'Files in cache' sorting")
  public FilesInCacheStep checkSorting() {
    tableStep.checkSelectedSorting(SECONDARY, ACCESS_COUNT, ASC)
        .checkColumnValuesIsSorted(SECONDARY, ACCESS_COUNT, ASC)
        .checkSorting(SECONDARY, ID)
        .checkSorting(SECONDARY, FILE_PATH)
        .checkSorting(SECONDARY, CACHED_TIME)
        .checkSorting(SECONDARY, LAST_ACCESSED_TIME)
        .checkSorting(SECONDARY, ACCESS_COUNT);
    return this;
  }

  @Step("Check 'Files in cache' pagination")
  public FilesInCacheStep checkPagination(List<String> expectedFileIdList) {
    tableStep.clickOnSortingColumn(SECONDARY, ID);
    paginationStep.checkPaginationFixture(SECONDARY, ID, expectedFileIdList, FILES_IN_CACHE_TOOLBAR);
    return this;
  }
}
