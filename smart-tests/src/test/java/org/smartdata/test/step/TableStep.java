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
import org.smartdata.test.element.TableElement;
import org.smartdata.test.model.TableColumn;
import org.springframework.stereotype.Service;

import static com.codeborne.selenide.CollectionCondition.size;
import static com.codeborne.selenide.Condition.visible;
import static io.arenadata.test.util.constant.TimeoutConstants.DEFAULT_WEB_ELEMENT_TIMEOUT;

@Slf4j
@Service
public class TableStep extends BaseWebStep {

  @Step("Check that current page's table is empty")
  public TableStep checkTableIsEmpty() {
    TableElement.TABLE_ROWS.shouldHave(size(0), DEFAULT_WEB_ELEMENT_TIMEOUT);
    TableElement.NODATA_ROW.shouldBe(visible, DEFAULT_WEB_ELEMENT_TIMEOUT);
    return this;
  }

  @Step("Check that page's table has {expectedRowsCount} rows")
  public TableStep checkTableRowsCountIs(int expectedRowsCount) {
    TableElement.TABLE_ROWS.shouldHave(size(expectedRowsCount), DEFAULT_WEB_ELEMENT_TIMEOUT);
    return this;
  }

  @Step("Check that page's table has '{matchingValue}' value in {columnIndex} column of the first row")
  public TableStep checkColumnValueInFirstRow(TableColumn column, String matchingValue) {
    checkElementTextIs(TableElement.getColumnInFirstRow(column.getIndex()), matchingValue);
    return this;
  }
}
