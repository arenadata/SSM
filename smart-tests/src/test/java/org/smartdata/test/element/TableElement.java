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
import org.smartdata.test.model.TableColumn;

import static com.codeborne.selenide.Condition.text;
import static com.codeborne.selenide.Selenide.$$x;
import static com.codeborne.selenide.Selenide.$x;

public interface TableElement {
  ElementsCollection TABLE_ROWS = $$x("//*[@data-test='table']//tbody//tr[not(@data-test='no-data')]");
  ElementsCollection SORTING_COLUMN_HEADERS = $$x("//*[@data-test='sorting']");
  SelenideElement NODATA_ROW = $x("//*[@data-test='table']//*[@data-test='no-data']");
  SelenideElement RESET_FILTER_BUTTON = $x("//*[.='Reset filter']");
  SelenideElement CHANGE_FREQUENCY_SELECT = $x("//*[contains(@class, 'frequencySelect')]//input");
  String ROW_CELL_WITH_INDEX_XPATH = "td[%d]";
  String ALL_COLUMN_CELL_BY_INDEX_XPATH = "//*[@data-test='table']//tbody//tr[not(@data-test='no-data')]//td[%d]";
  String SORTING_ARROW_XPATH = ".//*[contains(@class, 'sortingLabel')]";
  String COLUMN_HEADER_XPATH = "//*[@data-test='table']//th[@data-test='%s']";
  String FILTER_BUTTON_XPATH = ".//button[contains(@class, 'tableFilter')]";
  String GREEN_STATUS_MARKER_XPATH = ".//*[contains(@class, 'statusMarker_green')]";
  String GRAY_STATUS_MARKER_XPATH = ".//*[contains(@class, 'statusMarker_gray')]";
  String BLUE_STATUS_MARKER_XPATH = ".//*[contains(@class, 'statusMarker_blue')]";
  String CHANGE_FREQUENCY_OPTION_XPATH = "//*[@data-test='options']//li[.='%s sec']";

  static SelenideElement getColumnInFirstRow(TableColumn tableColumn) {
    return getCellFromRow(TABLE_ROWS.first(), tableColumn);
  }

  static SelenideElement getCellFromRow(SelenideElement row, TableColumn tableColumn) {
    return row.$x(String.format(ROW_CELL_WITH_INDEX_XPATH, tableColumn.getIndex() + 1));
  }

  static ElementsCollection getAllColumnCells(TableColumn tableColumn) {
    return $$x(String.format(ALL_COLUMN_CELL_BY_INDEX_XPATH, tableColumn.getIndex() + 1));
  }

  static SelenideElement getSortingColumnHeader(TableColumn tableColumn) {
    return SORTING_COLUMN_HEADERS.findBy(text(tableColumn.getName()));
  }

  static SelenideElement getColumnHeader(TableColumn tableColumn) {
    return $x(String.format(COLUMN_HEADER_XPATH, tableColumn.getHeaderId()));
  }

  static SelenideElement getFilterButton(TableColumn tableColumn) {
    return getColumnHeader(tableColumn).$x(FILTER_BUTTON_XPATH);
  }

  static SelenideElement getFrequencyOption(int sec) {
    return $x(String.format(CHANGE_FREQUENCY_OPTION_XPATH, sec));
  }
}
