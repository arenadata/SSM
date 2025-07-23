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

import static com.codeborne.selenide.Selenide.$$x;
import static com.codeborne.selenide.Selenide.$x;

public interface TableElement {
  ElementsCollection TABLE_ROWS = $$x("//*[@data-test='table']//tbody//tr[not(@data-test='no-data')]");
  SelenideElement NODATA_ROW = $x("//*[@data-test='table']//*[@data-test='no-data']");
  String ROW_CELL_WITH_INDEX_XPATH = "td[%d]";

  static SelenideElement getColumnInFirstRow(int columnIndex) {
    return getCellFromRow(TABLE_ROWS.first(), columnIndex);
  }

  static SelenideElement getColumnInLastRow(int columnIndex) {
    return getCellFromRow(TABLE_ROWS.last(), columnIndex);
  }

  static SelenideElement getCellFromRow(SelenideElement row, int columnIndex) {
    return row.$x(String.format(ROW_CELL_WITH_INDEX_XPATH, columnIndex + 1));
  }
}
