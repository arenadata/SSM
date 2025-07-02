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
import org.smartdata.client.generated.model.ActionSortDto;
import org.smartdata.client.generated.model.ActionSourceDto;
import org.smartdata.client.generated.model.ActionStateDto;
import org.smartdata.client.generated.model.ActionsDto;
import org.smartdata.client.generated.model.CompletionTimeIntervalDto;
import org.smartdata.client.generated.model.ErrorResponseDto;
import org.smartdata.client.generated.model.PageRequestDto;
import org.smartdata.client.generated.model.StartTimeIntervalDto;
import org.smartdata.client.generated.model.SubmissionTimeIntervalDto;
import org.smartdata.client.generated.model.SubmitActionRequestDto;
import org.smartdata.integration.api.ActionsApiWrapper;
import org.smartdata.integration.api.RulesApiWrapper;

import java.io.IOException;
import java.time.Duration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestActionRestApi extends IntegrationTestBase {

  private ActionsApiWrapper apiClient;
  private RulesApiWrapper rulesApi;

  private static final String ACTION_TEXT = "sleep -ms 10";

  @Before
  public void createApi() {
    apiClient = new ActionsApiWrapper();
    rulesApi = new RulesApiWrapper();
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
    apiClient.waitActionsTotalSize(1, Duration.ofMillis(100), Duration.ofSeconds(1));

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

  @Test
  public void testGetActionsPagination() {
    apiClient.submitAction(ACTION_TEXT);
    ActionInfoDto action = apiClient.submitAction(ACTION_TEXT);

    apiClient.waitActionsTotalSize(2, Duration.ofMillis(100), Duration.ofSeconds(1));

    ActionsDto actions = apiClient.rawClient()
        .getActions()
        .reqSpec(request -> request
            .addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, 1)
            .addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, 1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ActionsDto.class);

    assertEquals(2, actions.getTotal().longValue());
    assertEquals(1, actions.getItems().size());
    assertEquals(action.getId(), actions.getItems().get(0).getId());
  }

  @Test
  public void testGetActionsSortById() {
    ActionInfoDto firstAction = apiClient.submitAction(ACTION_TEXT);
    ActionInfoDto secondAction = apiClient.submitAction(ACTION_TEXT);

    apiClient.waitActionsTotalSize(2, Duration.ofMillis(100), Duration.ofSeconds(1));

    // ASC
    ActionsDto actions = apiClient.rawClient()
        .getActions()
        .sortQuery(ActionSortDto.ID)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ActionsDto.class);

    ActionInfoDto firstSortedAction = actions.getItems().get(0);
    ActionInfoDto secondSortedAction = actions.getItems().get(1);

    assertEquals(firstAction.getId(), firstSortedAction.getId());
    assertEquals(secondAction.getId(), secondSortedAction.getId());

    // DESC
    actions = apiClient.rawClient()
        .getActions()
        .sortQuery(ActionSortDto._ID)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ActionsDto.class);

    firstSortedAction = actions.getItems().get(0);
    secondSortedAction = actions.getItems().get(1);

    assertEquals(secondAction.getId(), firstSortedAction.getId());
    assertEquals(firstAction.getId(), secondSortedAction.getId());
  }

  @Test
  public void testGetActionsSortBySubmissionTime() {
    ActionInfoDto firstAction = apiClient.submitAction(ACTION_TEXT);
    ActionInfoDto secondAction = apiClient.submitAction(ACTION_TEXT);

    apiClient.waitActionsTotalSize(2, Duration.ofMillis(100), Duration.ofSeconds(1));

    // ASC
    ActionsDto actions = apiClient.rawClient()
        .getActions()
        .sortQuery(ActionSortDto.SUBMISSIONTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ActionsDto.class);

    ActionInfoDto firstSortedAction = actions.getItems().get(0);
    ActionInfoDto secondSortedAction = actions.getItems().get(1);

    assertEquals(firstAction.getId(), firstSortedAction.getId());
    assertEquals(secondAction.getId(), secondSortedAction.getId());

    // DESC
    actions = apiClient.rawClient()
        .getActions()
        .sortQuery(ActionSortDto._SUBMISSIONTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ActionsDto.class);

    firstSortedAction = actions.getItems().get(0);
    secondSortedAction = actions.getItems().get(1);

    assertEquals(secondAction.getId(), firstSortedAction.getId());
    assertEquals(firstAction.getId(), secondSortedAction.getId());
  }

  @Test
  public void testGetActionsSortByStartTime() {
    ActionInfoDto firstAction = apiClient.submitAction(ACTION_TEXT);
    apiClient.waitTillActionFinished(firstAction.getId(), Duration.ofMillis(100L), Duration.ofMillis(1000L));
    ActionInfoDto secondAction = apiClient.submitAction(ACTION_TEXT);
    apiClient.waitTillActionFinished(secondAction.getId(), Duration.ofMillis(100L), Duration.ofMillis(1000L));

    apiClient.waitActionsTotalSize(2, Duration.ofMillis(100), Duration.ofSeconds(1));

    // ASC
    ActionsDto actions = apiClient.rawClient()
        .getActions()
        .sortQuery(ActionSortDto.STARTTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ActionsDto.class);
    System.out.println(actions);

    ActionInfoDto firstSortedAction = actions.getItems().get(0);
    ActionInfoDto secondSortedAction = actions.getItems().get(1);

    assertEquals(firstAction.getId(), firstSortedAction.getId());
    assertEquals(secondAction.getId(), secondSortedAction.getId());

    // DESC
    actions = apiClient.rawClient()
        .getActions()
        .sortQuery(ActionSortDto._STARTTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ActionsDto.class);

    firstSortedAction = actions.getItems().get(0);
    secondSortedAction = actions.getItems().get(1);

    assertEquals(secondAction.getId(), firstSortedAction.getId());
    assertEquals(firstAction.getId(), secondSortedAction.getId());
  }

  @Test
  public void testGetActionsSortByCompletionTime() {
    ActionInfoDto firstAction = apiClient.submitAction(ACTION_TEXT);
    apiClient.waitTillActionFinished(firstAction.getId(), Duration.ofMillis(100L), Duration.ofMillis(1000L));
    ActionInfoDto secondAction = apiClient.submitAction(ACTION_TEXT);

    apiClient.waitActionsTotalSize(2, Duration.ofMillis(100), Duration.ofSeconds(1));

    // ASC
    ActionsDto actions = apiClient.rawClient()
        .getActions()
        .sortQuery(ActionSortDto.COMPLETIONTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ActionsDto.class);

    ActionInfoDto firstSortedAction = actions.getItems().get(0);
    ActionInfoDto secondSortedAction = actions.getItems().get(1);

    assertEquals(firstAction.getId(), firstSortedAction.getId());
    assertEquals(secondAction.getId(), secondSortedAction.getId());

    // DESC
    actions = apiClient.rawClient()
        .getActions()
        .sortQuery(ActionSortDto._COMPLETIONTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ActionsDto.class);

    firstSortedAction = actions.getItems().get(0);
    secondSortedAction = actions.getItems().get(1);

    assertEquals(secondAction.getId(), firstSortedAction.getId());
    assertEquals(firstAction.getId(), secondSortedAction.getId());
  }

  @Test
  public void testGetActionsFilterByTextRepresentationLike() {
    ActionInfoDto action = apiClient.submitAction(ACTION_TEXT);
    apiClient.submitAction("read -file /tmp/test.txt");

    apiClient.waitActionsTotalSize(2, Duration.ofMillis(100), Duration.ofSeconds(1));

    ActionsDto actions = apiClient.rawClient()
        .getActions()
        .textRepresentationLikeQuery("%sleep%")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ActionsDto.class);

    assertEquals(1, actions.getTotal().longValue());
    assertEquals(1, actions.getItems().size());

    ActionInfoDto fetchedAction = actions.getItems().get(0);
    assertEquals(action.getId(), fetchedAction.getId());
    assertEquals(action.getTextRepresentation(), fetchedAction.getTextRepresentation());
  }

  @Test
  public void testGetActionsFilterBySubmissionTime() {
    long start = System.currentTimeMillis();
    ActionInfoDto action = apiClient.submitAction(ACTION_TEXT);
    long end = System.currentTimeMillis();
    apiClient.submitAction(ACTION_TEXT);

    apiClient.waitActionsTotalSize(2, Duration.ofMillis(100), Duration.ofSeconds(1));

    ActionsDto actions = apiClient.rawClient()
        .getActions()
        .reqSpec(request -> request
            .addQueryParam(SubmissionTimeIntervalDto.JSON_PROPERTY_SUBMISSION_TIME_FROM, start)
            .addQueryParam(SubmissionTimeIntervalDto.JSON_PROPERTY_SUBMISSION_TIME_TO, end))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ActionsDto.class);

    assertEquals(1, actions.getTotal().longValue());
    assertEquals(1, actions.getItems().size());

    ActionInfoDto fetchedAction = actions.getItems().get(0);
    assertEquals(action.getId(), fetchedAction.getId());
    assertEquals(action.getTextRepresentation(), fetchedAction.getTextRepresentation());
  }

  @Test
  public void testGetActionsFilterByStartTime() {
    long start = System.currentTimeMillis();
    ActionInfoDto action = apiClient.submitAction(ACTION_TEXT);
    apiClient.waitTillActionFinished(action.getId(), Duration.ofMillis(100L), Duration.ofMillis(1000L));
    long end = System.currentTimeMillis();
    apiClient.submitAction(ACTION_TEXT);

    apiClient.waitActionsTotalSize(2, Duration.ofMillis(100), Duration.ofSeconds(1));

    ActionsDto actions = apiClient.rawClient()
        .getActions()
        .reqSpec(request -> request
            .addQueryParam(StartTimeIntervalDto.JSON_PROPERTY_START_TIME_FROM, start)
            .addQueryParam(StartTimeIntervalDto.JSON_PROPERTY_START_TIME_TO, end))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ActionsDto.class);

    assertEquals(1, actions.getTotal().longValue());
    assertEquals(1, actions.getItems().size());

    ActionInfoDto fetchedAction = actions.getItems().get(0);
    assertEquals(action.getId(), fetchedAction.getId());
    assertEquals(action.getTextRepresentation(), fetchedAction.getTextRepresentation());
  }

  @Test
  public void testGetActionsFilterByCompletionTime() {
    long start = System.currentTimeMillis();
    ActionInfoDto action = apiClient.submitAction(ACTION_TEXT);
    apiClient.waitTillActionFinished(action.getId(), Duration.ofMillis(100L), Duration.ofMillis(1000L));
    long end = System.currentTimeMillis();
    apiClient.submitAction(ACTION_TEXT);

    apiClient.waitActionsTotalSize(2, Duration.ofMillis(100), Duration.ofSeconds(1));

    ActionsDto actions = apiClient.rawClient()
        .getActions()
        .reqSpec(request -> request
            .addQueryParam(CompletionTimeIntervalDto.JSON_PROPERTY_COMPLETION_TIME_FROM, start)
            .addQueryParam(CompletionTimeIntervalDto.JSON_PROPERTY_COMPLETION_TIME_TO, end))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ActionsDto.class);

    assertEquals(1, actions.getTotal().longValue());
    assertEquals(1, actions.getItems().size());

    ActionInfoDto fetchedAction = actions.getItems().get(0);
    assertEquals(action.getId(), fetchedAction.getId());
    assertEquals(action.getTextRepresentation(), fetchedAction.getTextRepresentation());
  }

  @Test
  public void testGetActionsFilterByStates() {
    ActionInfoDto action = apiClient.submitAction(ACTION_TEXT);
    apiClient.submitAction("read -file nonexistent.file");

    apiClient.waitActionsTotalSize(2, Duration.ofMillis(100), Duration.ofSeconds(1));

    ActionsDto actions = apiClient.rawClient()
        .getActions()
        .statesQuery(ActionStateDto.SUCCESSFUL)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ActionsDto.class);

    assertEquals(1, actions.getTotal().longValue());
    assertEquals(1, actions.getItems().size());

    ActionInfoDto fetchedAction = actions.getItems().get(0);
    assertEquals(action.getId(), fetchedAction.getId());
    assertEquals(action.getTextRepresentation(), fetchedAction.getTextRepresentation());
  }

  @Test
  public void testGetActionsFilterBySources() {
    ActionInfoDto action = apiClient.submitAction(ACTION_TEXT);
    rulesApi.waitTillRuleTriggered(
        "file: at now | path matches \"/*\" | sleep -ms 10",
        Duration.ofMillis(100),
        Duration.ofSeconds(2));

    apiClient.waitActionsTotalSize(2, Duration.ofMillis(100), Duration.ofSeconds(1));

    ActionsDto actions = apiClient.rawClient()
        .getActions()
        .sourcesQuery(ActionSourceDto.USER)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(ActionsDto.class);

    assertEquals(1, actions.getTotal().longValue());
    assertEquals(1, actions.getItems().size());

    ActionInfoDto fetchedAction = actions.getItems().get(0);
    assertEquals(action.getId(), fetchedAction.getId());
    assertEquals(action.getTextRepresentation(), fetchedAction.getTextRepresentation());
  }

  @Test
  public void testGetActionsPaginationWithIncorrectValue() {
    ErrorResponseDto errorResponse = apiClient.rawClient()
        .getActions()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, 0))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertEquals("must be greater than or equal to 1", errorResponse.getMessage());

    errorResponse = apiClient.rawClient()
        .getActions()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, -1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertEquals("must be greater than or equal to 1", errorResponse.getMessage());

    errorResponse = apiClient.rawClient()
        .getActions()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, -1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertEquals("must be greater than or equal to 0", errorResponse.getMessage());

    errorResponse = apiClient.rawClient()
        .getActions()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, "string"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertTrue(errorResponse.getMessage().contains("Failed to convert property value of type"));

    errorResponse = apiClient.rawClient()
        .getActions()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, "string"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertTrue(errorResponse.getMessage().contains("Failed to convert property value of type"));
  }

  @Test
  public void testGetActionsSortByIncorrectQuery() {
    ErrorResponseDto errorResponse = apiClient.rawClient()
        .getActions()
        .sortQuery("nonexistent")
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertTrue(errorResponse.getMessage().contains("Failed to convert value of type"));
    assertTrue(errorResponse.getMessage().contains("Unexpected value 'nonexistent'"));
  }

  @Test
  public void testGetActionsFilterByIncorrectQuery() {
    ErrorResponseDto errorResponse = apiClient.rawClient()
        .getActions()
        .statesQuery("nonexistent")
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertTrue(errorResponse.getMessage().contains("Failed to convert value of type"));
    assertTrue(errorResponse.getMessage().contains("Unexpected value 'nonexistent'"));


    errorResponse = apiClient.rawClient()
        .getActions()
        .sourcesQuery("nonexistent")
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertTrue(errorResponse.getMessage().contains("Failed to convert value of type"));
    assertTrue(errorResponse.getMessage().contains("Unexpected value 'nonexistent'"));
  }

  @Test
  public void testAddIncorrectAction() {
    ErrorResponseDto errorResponse = apiClient.rawClient()
        .submitAction()
        .body(new SubmitActionRequestDto().action("INCORRECT_ACTION"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertEquals("Error parsing cmdlet: INCORRECT_ACTION. Unknown actions used in cmdlet: [INCORRECT_ACTION]",
        errorResponse.getMessage());
  }
}
