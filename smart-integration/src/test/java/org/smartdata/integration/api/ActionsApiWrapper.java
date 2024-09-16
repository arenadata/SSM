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
package org.smartdata.integration.api;

import io.restassured.response.Response;
import org.eclipse.jetty.http.HttpStatus;
import org.smartdata.client.generated.api.ActionsApi;
import org.smartdata.client.generated.invoker.ApiClient;
import org.smartdata.client.generated.model.ActionDto;
import org.smartdata.client.generated.model.ActionInfoDto;
import org.smartdata.client.generated.model.ActionStateDto;
import org.smartdata.client.generated.model.ActionsDto;
import org.smartdata.client.generated.model.SubmitActionRequestDto;

import java.time.Duration;

import static org.smartdata.integration.IntegrationTestBase.retryUntil;

public class ActionsApiWrapper {

  private final ActionsApi apiClient;

  public ActionsApiWrapper() {
    this(ApiClient.Config.apiConfig());
  }

  public ActionsApiWrapper(ApiClient.Config config) {
    this.apiClient = ApiClient.api(config).actions();
  }

  public ActionDto getAction(long actionId) {
    return apiClient.getAction()
        .idPath(actionId)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .executeAs(Response::andReturn);
  }

  public ActionsDto getActions() {
    return apiClient.getActions()
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .executeAs(Response::andReturn);
  }

  public ActionInfoDto submitAction(String actionText) {
    return apiClient.submitAction()
        .body(new SubmitActionRequestDto().action(actionText))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .executeAs(Response::andReturn);
  }

  public ActionDto waitTillActionFinished(String actionText, Duration interval, Duration timeout) {
    ActionInfoDto actionInfo = submitAction(actionText);
    return waitTillActionFinished(actionInfo.getId(), interval, timeout);
  }

  public ActionDto waitTillActionFinished(long actionId, Duration interval, Duration timeout) {
    return retryUntil(
        () -> getAction(actionId),
        action -> action.getState() != ActionStateDto.RUNNING,
        interval,
        timeout
    );
  }

  public ActionsApi rawClient() {
    return apiClient;
  }
}
