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

import io.arenadata.test.step.BaseWebStep;
import io.qameta.allure.Step;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import static org.smartdata.test.element.ActionsPageElement.SUBMIT_ACTION_BUTTON;
import static org.smartdata.test.element.ActionsPageElement.SUBMIT_ACTION_DIALOG;
import static org.smartdata.test.element.ActionsPageElement.SUBMIT_ACTION_DIALOG_CANCEL_BUTTON;
import static org.smartdata.test.element.ActionsPageElement.SUBMIT_ACTION_DIALOG_CREATE_BUTTON;
import static org.smartdata.test.element.ActionsPageElement.SUBMIT_ACTION_DIALOG_INPUT;

@Slf4j
@Service
public class ActionsStep extends BaseWebStep {

  @Step("Check 'Run' button on submit action dialog")
  public ActionsStep checkSubmitDialogRunButton(String actionText) {
    waitAndClick(SUBMIT_ACTION_BUTTON);
    waitVisibility(SUBMIT_ACTION_DIALOG);
    waitAndWrite(SUBMIT_ACTION_DIALOG_INPUT, actionText);
    waitAndClick(SUBMIT_ACTION_DIALOG_CREATE_BUTTON);
    waitDisappear(SUBMIT_ACTION_DIALOG);
    return this;
  }

  @Step("Check 'Cancel' button on submit action dialog")
  public ActionsStep checkSubmitDialogCancelButton(String actionText) {
    waitAndClick(SUBMIT_ACTION_BUTTON);
    waitVisibility(SUBMIT_ACTION_DIALOG);
    waitAndWrite(SUBMIT_ACTION_DIALOG_INPUT, actionText);
    waitAndClick(SUBMIT_ACTION_DIALOG_CANCEL_BUTTON);
    waitDisappear(SUBMIT_ACTION_DIALOG);
    return this;
  }

}
