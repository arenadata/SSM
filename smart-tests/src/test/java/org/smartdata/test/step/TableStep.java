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

import com.codeborne.selenide.SelenideElement;
import io.arenadata.test.step.BaseWebStep;
import io.arenadata.test.util.Utils;
import io.arenadata.test.util.constant.TimeoutConstants;
import io.qameta.allure.Step;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.math.NumberUtils;
import org.smartdata.test.element.TableElement;
import org.smartdata.test.model.TableColumn;
import org.springframework.stereotype.Service;

import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

import static com.codeborne.selenide.CollectionCondition.texts;
import static com.codeborne.selenide.Condition.attributeMatching;
import static io.arenadata.test.util.constant.TimeoutConstants.DEFAULT_WEB_ELEMENT_TIMEOUT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.smartdata.test.element.TableElement.NODATA_ROW;
import static org.smartdata.test.element.TableElement.SORTING_ARROW_XPATH;
import static org.smartdata.test.element.TableElement.TABLE_ROWS;
import static org.smartdata.test.element.TableElement.getAllColumnCells;
import static org.smartdata.test.element.TableElement.getSortingColumnHeader;

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

  @Step("Set sorting on {column} column")
  public TableStep setSortingColumn(TableColumn column) {
    waitAndClick(getSortingColumnHeader(column));
    return this;
  }

  @Step("Check sorting indicator on {column} column is ascending = {asc}")
  public TableStep checkSelectedSorting(TableColumn column, boolean asc) {
    SelenideElement columnHeader = getSortingColumnHeader(column);
    columnHeader.shouldHave(attributeMatching("class", ".*is-sorted.*"), DEFAULT_WEB_ELEMENT_TIMEOUT);
    if (asc) {
      columnHeader.$x(SORTING_ARROW_XPATH)
          .shouldNotHave(attributeMatching("class", ".*arrow_desc.*"), DEFAULT_WEB_ELEMENT_TIMEOUT);
    } else {
      columnHeader.$x(SORTING_ARROW_XPATH)
          .shouldHave(attributeMatching("class", ".*arrow_desc.*"), DEFAULT_WEB_ELEMENT_TIMEOUT);
    }
    return this;
  }

  @Step("Check that values in {column} column are sorted in ascending = {asc} order")
  public TableStep checkColumnValuesIsSorted(TableColumn column, boolean asc) {
    Utils.waitUntil(() -> {
      List<String> cellTexts = getAllColumnCells(column).asFixedIterable().stream()
          .map(SelenideElement::getText)
          .filter(s -> !s.isEmpty())
          .map(String::toLowerCase)
          .collect(Collectors.toList());

      Comparator<?> comparator = asc ? Comparator.naturalOrder() : Comparator.reverseOrder();

      if (cellTexts.stream().allMatch(NumberUtils::isCreatable)) {
        List<Double> numbers = cellTexts.stream().map(Double::parseDouble).collect(Collectors.toList());
        assertThat(numbers).isSortedAccordingTo((Comparator<Double>) comparator);
      } else {
        assertThat(cellTexts).isSortedAccordingTo((Comparator<String>) comparator);
      }
    }, TimeoutConstants.SHORT_WAIT_PARAMS);
    return this;
  }

  @Step("Check default sorting on {tableColumn} column")
  public TableStep checkDefaultSorting(TableColumn tableColumn) {
    checkSelectedSorting(tableColumn, false)
        .checkColumnValuesIsSorted(tableColumn, false)
        .setSortingColumn(tableColumn)
        .checkSelectedSorting(tableColumn, true)
        .checkColumnValuesIsSorted(tableColumn, true);
    return this;
  }

  @Step("Check sorting toggling on {tableColumn} column")
  public TableStep checkSorting(TableColumn tableColumn) {
    setSortingColumn(tableColumn)
        .checkSelectedSorting(tableColumn, true)
        .checkColumnValuesIsSorted(tableColumn, true)
        .setSortingColumn(tableColumn)
        .checkSelectedSorting(tableColumn, false)
        .checkColumnValuesIsSorted(tableColumn, false);
    return this;
  }
}
