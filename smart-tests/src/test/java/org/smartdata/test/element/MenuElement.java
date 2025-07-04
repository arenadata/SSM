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

import static com.codeborne.selenide.Selenide.$x;

public interface MenuElement {
  SelenideElement USERNAME = $x("//*[contains(@class, 'systemMenu')]//button[1]//*[contains(@class, 'leftBarMenuItem__label')]");
  SelenideElement DOCUMENTATION_BUTTON = $x("//*[contains(@class, 'systemMenu')]//a[.='Documentation']");
  SelenideElement RULES_BUTTON = $x("//*[contains(@class, 'leftBarMenuItem')]//*[.='Rules']");
  SelenideElement LOGOUT_BUTTON = $x("//*[contains(@class, 'systemMenu')]//button[.='Log Out']");
  SelenideElement LOGOUT_CONFIRMATION_MODAL = $x("//*[@data-test='dialog-container']");
  SelenideElement LOGOUT_CONFIRMATION_MESSAGE = LOGOUT_CONFIRMATION_MODAL.$x(".//h2");
  SelenideElement LOGOUT_ACCEPT_BUTTON = LOGOUT_CONFIRMATION_MODAL.$x(".//button[@data-test='btn-accept']");
  SelenideElement LOGOUT_REJECT_BUTTON = LOGOUT_CONFIRMATION_MODAL.$x(".//button[@data-test='btn-reject']");
  SelenideElement LOGOUT_CONFIRMATION_MODAL_X_BUTTON = LOGOUT_CONFIRMATION_MODAL.$x(".//button[contains(@class, 'dialog__close')]");
}
