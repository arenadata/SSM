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
package org.smartdata.integration;

import io.restassured.response.Response;
import org.apache.hadoop.fs.Path;
import org.eclipse.jetty.http.HttpStatus;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.client.generated.model.ActionDto;
import org.smartdata.client.generated.model.ActionInfoDto;
import org.smartdata.client.generated.model.ActionSourceDto;
import org.smartdata.client.generated.model.ActionStateDto;
import org.smartdata.client.generated.model.ActionsDto;
import org.smartdata.integration.api.ActionsApiWrapper;

import java.io.IOException;
import java.time.Duration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestActionRestApi extends IntegrationTestBase {

  private ActionsApiWrapper apiClient;

  @Before
  public void createApi() {
    apiClient = new ActionsApiWrapper();
  }

  @Test
  public void testSubmitGetAction() throws IOException {
    cluster.getFileSystem()
        .createNewFile(new Path("/tmp/text.txt"));

    String actionText = "read -file /tmp/text.txt";
    ActionInfoDto actionInfo = apiClient.submitAction(actionText);

    assertEquals(ActionSourceDto.USER, actionInfo.getSource());

    ActionDto actionDto = apiClient.waitTillActionFinished(actionInfo.getId(),
        Duration.ofMillis(100L), Duration.ofMillis(1000L));

    assertEquals(actionInfo.getId(), actionDto.getId());
    assertEquals(actionText, actionDto.getTextRepresentation());
    assertEquals(ActionStateDto.SUCCESSFUL, actionDto.getState());
  }

  @Test
  public void testSubmitGetActions() throws IOException {
    ActionsDto actions = apiClient.getActions();
    assertEquals(0L, actions.getTotal().longValue());
    assertTrue(actions.getItems().isEmpty());

    cluster.getFileSystem()
        .createNewFile(new Path("/tmp/text.txt"));

    String actionText = "read -file /tmp/text.txt";
    ActionInfoDto actionInfo = apiClient.submitAction(actionText);


    // we have to wait a bit, because of async cmdlets transfer
    // from in-memory cache to metastore
    retryUntil(
        () -> apiClient.getActions().getTotal().longValue(),
        total -> total == 1,
        Duration.ofMillis(100),
        Duration.ofSeconds(1)
    );

    actions = apiClient.getActions();
    assertEquals(1L, actions.getItems().size());
    assertEquals(actionInfo.getId(), actions.getItems().get(0).getId());
  }

  @Test
  public void testReturnNotFoundOnUnknownId() {
    apiClient.rawClient()
        .getAction()
        .idPath(777)
        .respSpec(response -> response.expectStatusCode(HttpStatus.NOT_FOUND_404))
        .execute(Response::andReturn);
  }
}
