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

public interface RulesPageElement {
  SelenideElement CREATE_RULE_BUTTON = $x("//button[.='Create rule']");
  SelenideElement CREATE_RULE_DIALOG_TITLE = $x("//*[contains(@class, 'title') and .='Create Rule']");
  SelenideElement CREATE_RULE_DIALOG_INPUT = $x("//*[@data-mode-id='ssmrule']//textarea");
  SelenideElement CREATE_RULE_DIALOG_CREATE_BUTTON = $x("//*[@data-test='btn-accept']");
  SelenideElement CREATE_RULE_DIALOG_CANCEL_BUTTON = $x("//*[@data-test='btn-reject']");
  SelenideElement RULES_COUNTER_CARD =
      $x("//*[contains(@class, 'legendCard') and not(contains(@class, 'secondary'))]//*[contains(@class, 'count')]");

  @Getter
  enum RulesTableColumn implements TableColumn {
    ID("ID", "id"),
    RULE_TEXT("Rule Text", "textRepresentation"),
    SUBMISSION_TIME("Submission Time", "submitTime"),
    LAST_CHECK_TIME("Last Check Time", "lastActivationTime"),
    CHECKED_NUMBER("Checked number", "activationCount"),
    CMDLETS_GENERATED("Cmdlets Generated", "cmdletsGenerated"),
    STATUS("Status", "state"),
    ACTIONS("Actions", "actions");

    private final String name;
    private final String headerId;

    RulesTableColumn(String name, String headerId) {
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
