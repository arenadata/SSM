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
package org.smartdata.test.suite.web;

import io.arenadata.test.model.UserRole;
import io.qameta.allure.Feature;
import io.qameta.allure.Story;
import io.qameta.allure.TmsLink;
import org.smartdata.test.step.LoginStep;
import org.smartdata.test.step.MenuStep;
import org.smartdata.test.suite.SsmBaseSuite;
import org.springframework.beans.factory.annotation.Autowired;
import org.testng.annotations.Test;

@Feature("Common functions")
public class CommonSuite extends SsmBaseSuite {

  @Autowired
  private LoginStep loginStep;

  @Autowired
  private MenuStep menuStep;

  @TmsLink("90211")
  @Story("Authorization")
  @Test(description = "Login and Logout")
  public void testLoginLogout() {
    loginStep.loginAs(UserRole.OWNER);
    menuStep.checkLogoutCancel(UserRole.OWNER)
        .logout();
    loginStep.loginAs(UserRole.KERBEROS);
  }

  @TmsLink("91396")
  @Story("Main Menu")
  @Test(description = "Documentation button")
  public void testDocumentationButton() {
    loginStep.loginAs(UserRole.OWNER);
    menuStep.openDocumentation()
        .checkDocumentationIsOpened();
  }
}
