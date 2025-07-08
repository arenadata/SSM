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

import com.codeborne.selenide.CollectionCondition;
import com.codeborne.selenide.Condition;
import com.codeborne.selenide.Selenide;
import io.arenadata.test.step.BaseWebStep;
import io.qameta.allure.Step;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.smartdata.test.element.TableElement;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class TableStep extends BaseWebStep {

  @Step("Check that current page's table is empty")
  public TableStep checkTableIsEmpty(boolean withPageRefresh) {
    if (withPageRefresh) {
      Selenide.refresh();
    }
    TableElement.TABLE_ROWS.shouldHave(CollectionCondition.size(0));
    TableElement.NODATA_ROW.shouldBe(Condition.visible);
    return this;
  }

  @Step("Check that page's table has {expectedRowsCount} rows")
  public TableStep checkTableRowsCountIs(int expectedRowsCount) {
    TableElement.TABLE_ROWS.shouldHave(CollectionCondition.size(expectedRowsCount));
    return this;
  }

  @Step("Check that page's table has \"{matchingValue}\" value in {columnIndex} column of the first row")
  public TableStep checkColumnValueInFirstRow(int columnIndex, String matchingValue) {
    TableElement.getColumnInFirstRow(columnIndex).shouldHave(Condition.exactText(matchingValue));
    return this;
  }
}
