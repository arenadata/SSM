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
import org.smartdata.test.element.TableElement;
import org.smartdata.test.model.TableColumn;
import org.springframework.stereotype.Service;

import java.util.List;

import static com.codeborne.selenide.CollectionCondition.texts;
import static io.arenadata.test.util.constant.TimeoutConstants.DEFAULT_WEB_ELEMENT_TIMEOUT;
import static org.smartdata.test.element.TableElement.NODATA_ROW;
import static org.smartdata.test.element.TableElement.TABLE_ROWS;
import static org.smartdata.test.element.TableElement.getAllColumnCells;

@Slf4j
@Service
public class TableStep extends BaseWebStep {

  @Step("Check that current page's table is empty")
  public TableStep checkTableIsEmpty() {
    checkSize(TABLE_ROWS, 0);
    waitVisibility(NODATA_ROW);
    return this;
  }

  @Step("Check that page's table has {expectedRowsCount} rows")
  public TableStep checkTableRowsCountIs(int expectedRowsCount) {
    checkSize(TABLE_ROWS, expectedRowsCount);
    return this;
  }

  @Step("Check that page's table has '{matchingValue}' value in {column} column of the first row")
  public TableStep checkColumnValueInFirstRow(TableColumn column, String matchingValue) {
    checkElementTextIs(TableElement.getColumnInFirstRow(column), matchingValue);
    return this;
  }

  @Step("Check table has row values in {column} column with table order")
  public TableStep checkColumnValues(TableColumn column, List<String> expectedValues) {
    getAllColumnCells(column).shouldHave(texts(expectedValues), DEFAULT_WEB_ELEMENT_TIMEOUT);
    return this;
  }
}
