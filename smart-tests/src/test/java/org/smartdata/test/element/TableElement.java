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
package org.smartdata.test.element;

import com.codeborne.selenide.ElementsCollection;
import com.codeborne.selenide.SelenideElement;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.smartdata.test.model.TableColumn;

import static com.codeborne.selenide.Condition.text;
import static com.codeborne.selenide.Selenide.$x;
import static org.smartdata.test.element.TableElement.TableType.PRIMARY;
import static org.smartdata.test.util.WebElementUtil.findFromBaseElement;

public interface TableElement {
  SelenideElement NODATA_ROW = $x("//*[@data-qa='table']//*[@data-qa='no-data']");
  SelenideElement CHANGE_FREQUENCY_SELECT = $x("//*[contains(@class, 'frequencySelect')]//input");
  String RESET_FILTER_BUTTON_XPATH = ".//*[.='Reset filter']";
  String TABLE_ROWS_XPATH = ".//tbody//tr[not(@data-qa='no-data')]";
  String SORTING_COLUMN_HEADERS = ".//*[@data-qa='sorting']";
  String ROW_CELL_WITH_INDEX_XPATH = "td[%d]";
  String ALL_COLUMN_CELL_BY_INDEX_XPATH = ".//tbody//tr[not(@data-qa='no-data')]//td[%d]";
  String SORTING_ARROW_XPATH = ".//*[contains(@class, 'sortingLabel')]";
  String COLUMN_HEADER_XPATH = ".//th[@data-qa='%s']";
  String FILTER_BUTTON_XPATH = ".//button[contains(@class, 'tableFilter')]";
  String GREEN_STATUS_MARKER_XPATH = ".//*[contains(@class, 'statusMarker_green')]";
  String GRAY_STATUS_MARKER_XPATH = ".//*[contains(@class, 'statusMarker_gray')]";
  String BLUE_STATUS_MARKER_XPATH = ".//*[contains(@class, 'statusMarker_blue')]";
  String CHANGE_FREQUENCY_OPTION_XPATH = "//*[@data-qa='options']//li[.='%s sec']";
  String TABLE_ROW_XPATH_BY_CELL_VALUE = ".//tbody//tr[td[@data-qa='%s']//*[text()='%s']]";

  static ElementsCollection getTableRows() {
    return getTableRows(PRIMARY);
  }

  static ElementsCollection getTableRows(TableType tableType) {
    return tableType.getTableRows();
  }

  static SelenideElement getCellInFirstRow(TableColumn tableColumn) {
    return getCellInFirstRow(PRIMARY, tableColumn);
  }

  static SelenideElement getCellInFirstRow(TableType tableType, TableColumn tableColumn) {
    return getCellFromRow(tableType.getTableRows().first(), tableColumn);
  }

  static SelenideElement getCellFromRow(SelenideElement row, TableColumn tableColumn) {
    return row.$x(String.format(ROW_CELL_WITH_INDEX_XPATH, tableColumn.getIndex() + 1));
  }

  static ElementsCollection getAllColumnCells(TableColumn tableColumn) {
    return getAllColumnCells(PRIMARY, tableColumn);
  }

  static ElementsCollection getAllColumnCells(TableType tableType, TableColumn tableColumn) {
    return $x(tableType.tableXpath).$$x(String.format(ALL_COLUMN_CELL_BY_INDEX_XPATH, tableColumn.getIndex() + 1));
  }

  static SelenideElement getSortingColumnHeader(TableColumn tableColumn) {
    return getSortingColumnHeader(PRIMARY, tableColumn);
  }

  static SelenideElement getSortingColumnHeader(TableType tableType, TableColumn tableColumn) {
    return $x(tableType.getTableXpath()).$$x(SORTING_COLUMN_HEADERS).findBy(text(tableColumn.getName()));
  }

  static SelenideElement getColumnHeader(TableType tableType, TableColumn tableColumn) {
    return $x(tableType.getTableXpath()).$x(String.format(COLUMN_HEADER_XPATH, tableColumn.getHeaderId()));
  }

  static SelenideElement getFilterButton(TableColumn tableColumn) {
    return getFilterButton(PRIMARY, tableColumn);
  }

  static SelenideElement getFilterButton(TableType tableType, TableColumn tableColumn) {
    return getColumnHeader(tableType, tableColumn).$x(FILTER_BUTTON_XPATH);
  }

  static SelenideElement getFrequencyOption(int sec) {
    return $x(String.format(CHANGE_FREQUENCY_OPTION_XPATH, sec));
  }

  static SelenideElement getResetFilterButton(SelenideElement baseElement) {
    return findFromBaseElement(baseElement, RESET_FILTER_BUTTON_XPATH);
  }

  static SelenideElement getRowByCellValue(TableColumn tableColumn, String value) {
    return $x(String.format(TABLE_ROW_XPATH_BY_CELL_VALUE, tableColumn.getCellId(), value));
  }

  @Getter
  @RequiredArgsConstructor
  enum TableType {
    PRIMARY("//*[@data-qa='table']"),
    CLUSTER_INFO("//*[@data-qa='cluster-info']"),
    HOTTEST_FILES("//*[@data-qa='hottest-files']"),
    FILES_IN_CACHE("//*[@data-qa='files-in-cache']");

    private final String tableXpath;

    public ElementsCollection getTableRows() {
      return $x(tableXpath).$$x(TABLE_ROWS_XPATH);
    }

    public SelenideElement getTableElement() {
      return $x(tableXpath);
    }
  }
}
