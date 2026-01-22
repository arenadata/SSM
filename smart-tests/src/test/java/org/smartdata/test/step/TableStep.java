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
import io.qameta.allure.Step;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.math.NumberUtils;
import org.smartdata.test.model.SortOrder;
import org.smartdata.test.model.TableColumn;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static com.codeborne.selenide.CollectionCondition.exactTexts;
import static com.codeborne.selenide.Condition.attributeMatching;
import static com.codeborne.selenide.Condition.not;
import static com.codeborne.selenide.Condition.text;
import static io.arenadata.test.util.Utils.waitUntil;
import static io.arenadata.test.util.constant.TimeoutConstants.DEFAULT_WEB_ELEMENT_TIMEOUT;
import static io.arenadata.test.util.constant.TimeoutConstants.SHORT_WAIT_PARAMS;
import static java.time.ZoneOffset.UTC;
import static org.assertj.core.api.Assertions.assertThat;
import static org.smartdata.test.element.TableElement.CHANGE_FREQUENCY_SELECT;
import static org.smartdata.test.element.TableElement.NODATA_ROW;
import static org.smartdata.test.element.TableElement.SORTING_ARROW_XPATH;
import static org.smartdata.test.element.TableElement.TableType;
import static org.smartdata.test.element.TableElement.TableType.PRIMARY;
import static org.smartdata.test.element.TableElement.getAllColumnCells;
import static org.smartdata.test.element.TableElement.getCellFromRow;
import static org.smartdata.test.element.TableElement.getCellInFirstRow;
import static org.smartdata.test.element.TableElement.getFilterButton;
import static org.smartdata.test.element.TableElement.getFrequencyOption;
import static org.smartdata.test.element.TableElement.getResetFilterButton;
import static org.smartdata.test.element.TableElement.getSortingColumnHeader;
import static org.smartdata.test.element.TableElement.getTableRows;
import static org.smartdata.test.element.TableFilterPopupElement.DATA_PICKER_PANEL;
import static org.smartdata.test.model.SortOrder.ASC;
import static org.smartdata.test.model.SortOrder.DESC;
import static org.smartdata.test.util.constant.CommonConstants.DATE_TIME_FORMATTER_UI;

@Slf4j
@Service
public class TableStep extends BaseWebStep {

  @Step("Check that current page's table is empty")
  public TableStep checkTableIsEmpty() {
    checkSize(getTableRows(), 0);
    waitVisibility(NODATA_ROW);
    return this;
  }

  @Step("Check that page's table has {expectedRowsCount} rows")
  public TableStep checkTableRowsCountIs(int expectedRowsCount) {
    checkTableRowsCountIs(PRIMARY, expectedRowsCount);
    return this;
  }

  @Step("Check that page's {tableType} table has {expectedRowsCount} rows")
  public TableStep checkTableRowsCountIs(TableType tableType, int expectedRowsCount) {
    checkSize(getTableRows(tableType), expectedRowsCount);
    return this;
  }

  @Step("Check that page's table has '{matchingValue}' value in {column} column of the first row")
  public TableStep checkColumnValueInFirstRow(TableColumn column, String matchingValue) {
    checkColumnValueInFirstRow(PRIMARY, column, matchingValue);
    return this;
  }

  @Step("Check that page's table has '{matchingValue}' value in {tableType} table {column} column of the first row")
  public TableStep checkColumnValueInFirstRow(TableType tableType, TableColumn column, String matchingValue) {
    waitTextEquals(getCellInFirstRow(tableType, column), matchingValue);
    return this;
  }

  @Step("Check that page's table match '{pattern}' pattern in {column} column of the first row")
  public TableStep checkColumnValueInFirstRowMatchPattern(TableColumn column, String pattern) {
    String value = waitVisibility(getCellInFirstRow(column)).getText();
    assertThat(value).matches(pattern);
    return this;
  }

  @Step("Check table has row values {expectedValues} in {tableType} table {column} column with table order")
  public TableStep checkColumnValues(TableType tableType, TableColumn column, List<String> expectedValues) {
    getAllColumnCells(tableType, column).shouldHave(exactTexts(expectedValues), DEFAULT_WEB_ELEMENT_TIMEOUT);
    return this;
  }

  @Step("Check table has row value {expectedValue} in {column} column")
  public TableStep checkRowColumnValue(SelenideElement row, TableColumn column, String expectedValue) {
    waitTextEquals(getCellFromRow(row, column), expectedValue);
    return this;
  }

  @Step("Click sorting on {column} column")
  public TableStep clickOnSortingColumn(TableColumn column) {
    waitAndClick(getSortingColumnHeader(column));
    return this;
  }

  @Step("Click sorting on {tableType} table {column} column")
  public TableStep clickOnSortingColumn(TableType tableType, TableColumn column) {
    waitAndClick(getSortingColumnHeader(tableType, column));
    return this;
  }

  @Step("Check sorting indicator on {column} column is {sortOrder}")
  public TableStep checkSelectedSorting(TableColumn column, SortOrder sortOrder) {
    checkSelectedSorting(PRIMARY, column, sortOrder);
    return this;
  }

  @Step("Check sorting indicator on {tableType} table {column} column is {sortOrder}")
  public TableStep checkSelectedSorting(TableType tableType, TableColumn column, SortOrder sortOrder) {
    SelenideElement columnHeader = getSortingColumnHeader(tableType, column);
    columnHeader.shouldHave(attributeMatching("class", ".*is-sorted.*"), DEFAULT_WEB_ELEMENT_TIMEOUT);
    if (sortOrder == ASC) {
      columnHeader.$x(SORTING_ARROW_XPATH)
          .shouldNotHave(attributeMatching("class", ".*arrow_desc.*"), DEFAULT_WEB_ELEMENT_TIMEOUT);
    } else {
      columnHeader.$x(SORTING_ARROW_XPATH)
          .shouldHave(attributeMatching("class", ".*arrow_desc.*"), DEFAULT_WEB_ELEMENT_TIMEOUT);
    }
    return this;
  }

  @Step("Check that values in {column} column are sorted in {sortOrder} order")
  public TableStep checkColumnValuesIsSorted(TableColumn column, SortOrder sortOrder) {
    checkColumnValuesIsSorted(PRIMARY, column, sortOrder);
    return this;
  }

  @Step("Check that values in {tableType} table {column} column are sorted in {sortOrder} order")
  public TableStep checkColumnValuesIsSorted(TableType tableType, TableColumn column, SortOrder sortOrder) {
    waitUntil(() -> {
      List<String> cellTexts = getAllColumnCells(tableType, column).asFixedIterable().stream()
          .map(SelenideElement::getText)
          .filter(s -> !s.isEmpty())
          .map(String::toLowerCase)
          .collect(Collectors.toList());

      Comparator<?> comparator = sortOrder == ASC ? Comparator.naturalOrder() : Comparator.reverseOrder();

      if (cellTexts.stream().allMatch(NumberUtils::isCreatable)) {
        List<Double> numbers = cellTexts.stream().map(Double::parseDouble).collect(Collectors.toList());
        assertThat(numbers).isSortedAccordingTo((Comparator<Double>) comparator);
      } else {
        assertThat(cellTexts).isSortedAccordingTo((Comparator<String>) comparator);
      }
    }, SHORT_WAIT_PARAMS);
    return this;
  }

  @Step("Check that values in {column} column are sorted in {sortOrder} order using custom comparator")
  public TableStep checkColumnValuesIsSorted(TableType tableType, TableColumn column, SortOrder sortOrder,
                                             Comparator customComparator) {
    waitUntil(() -> {
      List<String> cellTexts = getAllColumnCells(tableType, column).asFixedIterable().stream()
          .map(SelenideElement::getText)
          .filter(s -> !s.isEmpty())
          .collect(Collectors.toList());

      Comparator comparator = sortOrder == ASC ? customComparator : customComparator.reversed();

      assertThat(cellTexts).isSortedAccordingTo(comparator);
    }, SHORT_WAIT_PARAMS);
    return this;
  }

  @Step("Check default sorting on {tableColumn} column")
  public TableStep checkDefaultSorting(TableColumn tableColumn) {
    checkDefaultSorting(PRIMARY, tableColumn);
    return this;
  }

  @Step("Check default sorting on {tableType} table {tableColumn} column")
  public TableStep checkDefaultSorting(TableType tableType, TableColumn tableColumn) {
    checkSelectedSorting(tableType, tableColumn, DESC)
        .checkColumnValuesIsSorted(tableType, tableColumn, DESC)
        .clickOnSortingColumn(tableType, tableColumn)
        .checkSelectedSorting(tableType, tableColumn, ASC)
        .checkColumnValuesIsSorted(tableType, tableColumn, ASC);
    return this;
  }

  @Step("Check sorting on {tableColumn} column")
  public TableStep checkSorting(TableColumn tableColumn) {
    checkSorting(PRIMARY, tableColumn);
    return this;
  }

  @Step("Check sorting on {tableColumn} column using custom comparator")
  public TableStep checkSorting(TableColumn tableColumn, Comparator customComparator) {
    checkSorting(PRIMARY, tableColumn, customComparator);
    return this;
  }

  @Step("Check sorting on {tableType} table {tableColumn} column")
  public TableStep checkSorting(TableType tableType, TableColumn tableColumn) {
    clickOnSortingColumn(tableType, tableColumn)
        .checkSelectedSorting(tableType, tableColumn, ASC)
        .checkColumnValuesIsSorted(tableType, tableColumn, ASC)
        .clickOnSortingColumn(tableType, tableColumn)
        .checkSelectedSorting(tableType, tableColumn, DESC)
        .checkColumnValuesIsSorted(tableType, tableColumn, DESC);
    return this;
  }

  @Step("Check sorting on {tableColumn} column using custom comparator")
  public TableStep checkSorting(TableType tableType, TableColumn tableColumn, Comparator customComparator) {
    clickOnSortingColumn(tableType, tableColumn)
        .checkSelectedSorting(tableType, tableColumn, ASC)
        .checkColumnValuesIsSorted(tableType, tableColumn, ASC, customComparator)
        .clickOnSortingColumn(tableType, tableColumn)
        .checkSelectedSorting(tableType, tableColumn, DESC)
        .checkColumnValuesIsSorted(tableType, tableColumn, DESC, customComparator);
    return this;
  }

  @Step("Click on {tableColumn} column filter button")
  public TableStep clickFilterButton(TableColumn tableColumn) {
    clickFilterButton(PRIMARY, tableColumn);
    return this;
  }

  @Step("Open {tableColumn} column filter panel")
  public TableStep openFilterPanel(TableColumn tableColumn) {
    waitUntil(() -> {
      clickFilterButton(PRIMARY, tableColumn);
      waitVisibility(DATA_PICKER_PANEL);
    }, SHORT_WAIT_PARAMS);
    return this;
  }

  @Step("Click on {tableType} table {tableColumn} column filter button")
  public TableStep clickFilterButton(TableType tableType, TableColumn tableColumn) {
    waitAndClick(getFilterButton(tableType, tableColumn));
    return this;
  }

  @Step("Click on 'Reset filter' button")
  public TableStep clickResetFilterButton() {
    clickResetFilterButton(null);
    return this;
  }

  @Step("Click on 'Reset filter' button")
  public TableStep clickResetFilterButton(SelenideElement baseElement) {
    waitAndClick(getResetFilterButton(baseElement));
    return this;
  }

  @Step("Check color marker in first row is visible")
  public TableStep checkColorStatusMarkerInFirstRow(TableColumn tableColumn, String statusMarkerXpath) {
    waitVisibility(getCellInFirstRow(tableColumn).$x(statusMarkerXpath));
    return this;
  }

  @Step("Check all {tableColumn} column values equal same expected value '{value}'")
  public TableStep checkAllColumnCellsTextEqual(int expectedRowsCount, TableColumn tableColumn, String value) {
    String[] expectedValues = new String[expectedRowsCount];
    Arrays.fill(expectedValues, value);
    getAllColumnCells(tableColumn).shouldHave(exactTexts(expectedValues), DEFAULT_WEB_ELEMENT_TIMEOUT);
    return this;
  }

  @Step("Check refreshing frequency for column with index {column}")
  public TableStep checkRefreshingFrequency(TableColumn column) {
    IntStream.of(10, 5, 2, 1).forEachOrdered(refreshPeriod -> {
      changeRefreshingFrequencyTo(refreshPeriod);
      waitUntil(() -> {
        SelenideElement firstTimeCell = getCellInFirstRow(column);
        String dateBeforeRefreshStr = firstTimeCell.getText();
        String dateAfterRefreshStr =
            firstTimeCell.shouldHave(not(text(dateBeforeRefreshStr)), DEFAULT_WEB_ELEMENT_TIMEOUT).getText();
        LocalDateTime dateBeforeRefresh = LocalDateTime.parse(dateBeforeRefreshStr, DATE_TIME_FORMATTER_UI);
        LocalDateTime dateAfterRefresh = LocalDateTime.parse(dateAfterRefreshStr, DATE_TIME_FORMATTER_UI);
        long diff = dateAfterRefresh.toEpochSecond(UTC) - dateBeforeRefresh.toEpochSecond(UTC);
        assertThat(diff).as("Actual refreshing period is not equal to the chosen one").isEqualTo(refreshPeriod);
      }, SHORT_WAIT_PARAMS);
    });
    return this;
  }

  @Step("Set refreshing frequency value to {value} sec")
  private void changeRefreshingFrequencyTo(int value) {
    waitAndClick(CHANGE_FREQUENCY_SELECT);
    waitAndClick(getFrequencyOption(value));
  }
}
