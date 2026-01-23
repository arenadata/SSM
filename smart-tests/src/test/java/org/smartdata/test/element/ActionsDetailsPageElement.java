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

import com.codeborne.selenide.SelenideElement;
import lombok.Getter;
import org.smartdata.test.model.TableColumn;

import static com.codeborne.selenide.Selenide.$x;

public interface ActionsDetailsPageElement {
  SelenideElement ACTION_DETAILS_RESULT_BUTTON = $x("//*[contains(@class, 'tabsBlock')]//*[.='Result']");
  SelenideElement ACTION_DETAILS_LOG_BUTTON = $x("//*[contains(@class, 'tabsBlock')]//*[.='Log']");
  SelenideElement ACTION_DETAILS_LOG_VIEW =
      $x("//*[contains(@class, 'simpleLogView') and not(contains(@class, 'actionExecutionInfo'))]");
  SelenideElement HEADER_TITLE_ACTION = $x("//*[contains(@class, 'actionHeader')]//h1");
  SelenideElement HEADER_TITLE_PARAMS = $x("//*[contains(@class, 'actionHeader') and contains(@class, 'text')]");
  SelenideElement HEADER_SUCCESSFUL_ICON = $x("//*[name()='use' and @*='#status-ok']");
  SelenideElement HEADER_RUNNING_ICON = $x("//*[name()='use' and @*='#status-running']");

  @Getter
  enum ActionsDetailsTableColumn implements TableColumn {
    ID("ID", "id", "id"),
    CREATE_TIME("Create Time", "submissionTime", "submissionTime"),
    FINISH_TIME("Finish Time", "completionTime", "completionTime"),
    RUNNING_TIME("Running Time", "runningTime", "passedTime"),
    STATUS("Status", "state", "state"),
    TYPE("Type", "source", "source"),
    HOST("Host", "execHost", "execHost"),
    ACTIONS("Actions", "actions", "actions");

    private final String name;
    private final String headerId;
    private final String cellId;

    ActionsDetailsTableColumn(String name, String headerId, String cellId) {
      this.name = name;
      this.headerId = headerId;
      this.cellId = cellId;
    }

    @Override
    public int getIndex() {
      return ordinal();
    }

    @Override
    public String toString() {
      return getName();
    }
  }
}
