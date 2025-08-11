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

public interface ActionsPageElement {
  SelenideElement SUBMIT_ACTION_BUTTON = $x("//button[.='Submit action']");
  SelenideElement SUBMIT_ACTION_DIALOG = $x("//*[.='Submit action']//ancestor::*[contains(@class, 'dialog')]");
  SelenideElement SUBMIT_ACTION_DIALOG_INPUT = SUBMIT_ACTION_DIALOG.$x(".//textarea");
  SelenideElement SUBMIT_ACTION_DIALOG_CREATE_BUTTON = SUBMIT_ACTION_DIALOG.$x(".//*[@data-test='btn-accept']");
  SelenideElement SUBMIT_ACTION_DIALOG_CANCEL_BUTTON = SUBMIT_ACTION_DIALOG.$x(".//*[@data-test='btn-reject']");

  @Getter
  enum ActionsTableColumn implements TableColumn {
    ID("ID", "id"),
    ACTION("Action", "textRepresentation"),
    HOST("Host", "execHost"),
    CREATE_TIME("Create Time", "submissionTime"),
    FINISH_TIME("Finish Time", "completionTime"),
    STATUS("Status", "state"),
    TYPE("Type", "source"),
    ACTIONS("Actions", "actions");

    private final String name;
    private final String headerId;

    ActionsTableColumn(String name, String headerId) {
      this.name = name;
      this.headerId = headerId;
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
