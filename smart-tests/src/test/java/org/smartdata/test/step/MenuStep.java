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

import com.codeborne.selenide.Selenide;
import com.codeborne.selenide.SelenideElement;
import io.arenadata.test.model.UserModel;
import io.arenadata.test.model.UserRole;
import io.arenadata.test.service.UserProvider;
import io.arenadata.test.step.BaseWebStep;
import io.arenadata.test.util.Utils;
import io.qameta.allure.Step;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import static com.codeborne.selenide.Selenide.$x;
import static io.arenadata.test.util.constant.TimeoutConstants.SHORT_WAIT_PARAMS;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.smartdata.test.element.MenuElement.DOCUMENTATION_BUTTON;
import static org.smartdata.test.element.MenuElement.LOGOUT_ACCEPT_BUTTON;
import static org.smartdata.test.element.MenuElement.LOGOUT_BUTTON;
import static org.smartdata.test.element.MenuElement.LOGOUT_CONFIRMATION_MESSAGE;
import static org.smartdata.test.element.MenuElement.LOGOUT_CONFIRMATION_MODAL;
import static org.smartdata.test.element.MenuElement.LOGOUT_CONFIRMATION_MODAL_X_BUTTON;
import static org.smartdata.test.element.MenuElement.LOGOUT_REJECT_BUTTON;
import static org.smartdata.test.element.MenuElement.RULES_BUTTON;
import static org.smartdata.test.element.MenuElement.USERNAME;

@Slf4j
@Service
@RequiredArgsConstructor
public class MenuStep extends BaseWebStep {

  @Autowired
  private UserProvider<UserRole> ssmUserProvider;

  @Step("Verify current user name in menu")
  public void checkUserInfo(UserModel<UserRole> userModel) {
    assertThat("Username doesn't match expected one", USERNAME.getText(), is(userModel.getLogin()));
  }

  @Step("Verify the user is still logged in after cancel logout")
  public MenuStep checkLogoutCancel(UserRole userRole) {
    UserModel<UserRole> userModel = ssmUserProvider.getUserModel(userRole);
    clickLogoutAndCancelWith(LOGOUT_REJECT_BUTTON);
    checkUserInfo(userModel);
    clickLogoutAndCancelWith(LOGOUT_CONFIRMATION_MODAL_X_BUTTON);
    checkUserInfo(userModel);
    return this;
  }

  @Step("Click Logout, verify confirmation modal and Cancel")
  public void clickLogoutAndCancelWith(SelenideElement cancelElement) {
    waitAndClick(LOGOUT_BUTTON);
    waitAppear(LOGOUT_CONFIRMATION_MODAL);
    checkElementTextIs(LOGOUT_CONFIRMATION_MESSAGE, "Are you sure you want to log out?");
    waitAndClick(cancelElement);
    waitDisappear(LOGOUT_CONFIRMATION_MODAL);
  }

  @Step("Log out")
  public MenuStep logout() {
    waitAndClick(LOGOUT_BUTTON);
    waitAndClick(LOGOUT_ACCEPT_BUTTON);
    waitDisappear(LOGOUT_CONFIRMATION_MODAL);
    return this;
  }

  @Step("Open Documentation")
  public MenuStep openDocumentation() {
    Utils.waitUntil(() -> {
      waitAndClick(DOCUMENTATION_BUTTON);
      Selenide.switchTo().window(1);
    }, SHORT_WAIT_PARAMS);
    return this;
  }

  @Step("Check Documentation is opened in new tab")
  public void checkDocumentationIsOpened() {
    checkElementTextIs($x("//h1"), "SSM architecture");
  }

  @Step("Open Rules page")
  public MenuStep openRulesPage() {
    waitAndClick(RULES_BUTTON);
    return this;
  }
}
