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
import org.smartdata.client.generated.api.CmdletsApi;
import org.smartdata.client.generated.invoker.ApiClient;
import org.smartdata.client.generated.model.CmdletDto;
import org.smartdata.client.generated.model.CmdletStateDto;
import org.smartdata.client.generated.model.CmdletsDto;
import org.smartdata.client.generated.model.SubmitCmdletRequestDto;

import java.time.Duration;

import static org.smartdata.integration.IntegrationTestBase.retryUntil;

public class CmdletsApiWrapper {

  private final CmdletsApi apiClient;

  public CmdletsApiWrapper() {
    this.apiClient = ApiClient.api(ApiClient.Config.apiConfig()).cmdlets();
  }

  public CmdletDto getCmdlet(long cmdletId) {
    return apiClient.getCmdlet()
        .idPath(cmdletId)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .executeAs(Response::andReturn);
  }

  public CmdletsDto getCmdlets() {
    return apiClient.getCmdlets()
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .executeAs(Response::andReturn);
  }

  public void deleteCmdlet(long cmdletId) {
    apiClient.deleteCmdlet()
        .idPath(cmdletId)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::andReturn);
  }

  public CmdletDto submitCmdlet(String cmdletText) {
    return apiClient.addCmdlet()
        .body(new SubmitCmdletRequestDto().cmdlet(cmdletText))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .executeAs(Response::andReturn);
  }

  public CmdletDto waitTillCmdletFinished(String cmdletText, Duration interval, Duration timeout) {
    CmdletDto cmdlet = submitCmdlet(cmdletText);
    return waitTillCmdletFinished(cmdlet.getId(), interval, timeout);
  }

  public CmdletDto waitTillCmdletFinished(long cmdletId, Duration interval, Duration timeout) {
    return retryUntil(
        () -> getCmdlet(cmdletId),
        cmdlet -> cmdlet.getState() == CmdletStateDto.CANCELLED
            || cmdlet.getState() == CmdletStateDto.DONE
            || cmdlet.getState() == CmdletStateDto.FAILED,
        interval,
        timeout
    );
  }

  public CmdletsApi rawClient() {
    return apiClient;
  }
}
