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
import org.eclipse.jetty.http.HttpStatus;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.client.generated.model.ActionInfoDto;
import org.smartdata.client.generated.model.AuditEventDto;
import org.smartdata.client.generated.model.AuditEventResultDto;
import org.smartdata.client.generated.model.AuditEventsDto;
import org.smartdata.client.generated.model.AuditObjectTypeDto;
import org.smartdata.client.generated.model.AuditOperationDto;
import org.smartdata.client.generated.model.AuditSortDto;
import org.smartdata.client.generated.model.EventTimeIntervalDto;
import org.smartdata.client.generated.model.PageRequestDto;
import org.smartdata.client.generated.model.RuleDto;
import org.smartdata.client.generated.model.SubmitActionRequestDto;
import org.smartdata.integration.api.ActionsApiWrapper;
import org.smartdata.integration.api.AuditApiWrapper;
import org.smartdata.integration.api.RulesApiWrapper;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestAuditRestApi extends IntegrationTestBase {

  private ActionsApiWrapper actionsApiClient;
  private RulesApiWrapper rulesApiClient;
  private AuditApiWrapper auditApiClient;

  private static final String RULE_TEXT = "file: path matches \"text1\" | read";
  private static final String ACTION_TEXT = "sleep -ms 10";

  @Before
  public void createApi() {
    actionsApiClient = new ActionsApiWrapper();
    rulesApiClient = new RulesApiWrapper();
    auditApiClient = new AuditApiWrapper();
  }

  @Test
  public void testGetEmptyAuditActions() {
    AuditEventsDto auditEvents = auditApiClient.getAuditEvents();

    assertEquals(0, auditEvents.getTotal().longValue());
    assertTrue(auditEvents.getItems().isEmpty());
  }

  @Test
  public void testGetAuditActions() {
    actionsApiClient.submitAction(ACTION_TEXT);
    RuleDto rule = rulesApiClient.submitRule(RULE_TEXT);

    rulesApiClient.startRule(rule.getId());
    rulesApiClient.stopRule(rule.getId());
    rulesApiClient.deleteRule(rule.getId());

    AuditEventsDto auditEvents = auditApiClient.getAuditEvents();

    assertEquals(5, auditEvents.getTotal().longValue());

    List<AuditOperationDto> expectedOperations = Arrays.asList(
        AuditOperationDto.START,
        AuditOperationDto.CREATE,
        AuditOperationDto.START,
        AuditOperationDto.STOP,
        AuditOperationDto.DELETE
    );

    List<AuditOperationDto> actualOperations = auditEvents.getItems().stream()
        .map(AuditEventDto::getOperation)
        .collect(Collectors.toList());

    assertEquals(expectedOperations, actualOperations);
  }

  @Test
  public void testGetAuditEventsPagination() {
    RuleDto rule = rulesApiClient.submitRule(RULE_TEXT);
    rulesApiClient.startRule(rule.getId());

    AuditEventsDto auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .reqSpec(request -> request
            .addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, 1)
            .addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, 1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(2, auditEvents.getTotal().longValue());
    assertEquals(1, auditEvents.getItems().size());

    AuditEventDto fetchedEvent = auditEvents.getItems().get(0);
    assertEquals(AuditOperationDto.START, fetchedEvent.getOperation());
  }

  @Test
  public void testGetAuditEventsSortById() {
    RuleDto rule = rulesApiClient.submitRule(RULE_TEXT);
    rulesApiClient.startRule(rule.getId());

    // ASC
    AuditEventsDto auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .sortQuery(AuditSortDto.ID)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(2, auditEvents.getItems().size());

    AuditEventDto firstSortedEvent = auditEvents.getItems().get(0);
    AuditEventDto secondSortedEvent = auditEvents.getItems().get(1);

    assertEquals(AuditOperationDto.CREATE, firstSortedEvent.getOperation());
    assertEquals(AuditOperationDto.START, secondSortedEvent.getOperation());

    // DESC
    auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .sortQuery(AuditSortDto._ID)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(2, auditEvents.getItems().size());

    firstSortedEvent = auditEvents.getItems().get(0);
    secondSortedEvent = auditEvents.getItems().get(1);

    assertEquals(AuditOperationDto.START, firstSortedEvent.getOperation());
    assertEquals(AuditOperationDto.CREATE, secondSortedEvent.getOperation());
  }

  @Test
  public void testGetAuditEventsSortByTimestamp() {
    RuleDto rule = rulesApiClient.submitRule(RULE_TEXT);
    rulesApiClient.startRule(rule.getId());

    // ASC
    AuditEventsDto auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .sortQuery(AuditSortDto.TIMESTAMP)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(2, auditEvents.getItems().size());

    AuditEventDto firstSortedEvent = auditEvents.getItems().get(0);
    AuditEventDto secondSortedEvent = auditEvents.getItems().get(1);

    assertEquals(AuditOperationDto.CREATE, firstSortedEvent.getOperation());
    assertEquals(AuditOperationDto.START, secondSortedEvent.getOperation());

    // DESC
    auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .sortQuery(AuditSortDto._TIMESTAMP)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(2, auditEvents.getItems().size());

    firstSortedEvent = auditEvents.getItems().get(0);
    secondSortedEvent = auditEvents.getItems().get(1);

    assertEquals(AuditOperationDto.START, firstSortedEvent.getOperation());
    assertEquals(AuditOperationDto.CREATE, secondSortedEvent.getOperation());
  }

  @Test
  public void testGetAuditEventsSortByObjectType() {
    rulesApiClient.submitRule(RULE_TEXT);
    actionsApiClient.submitAction(ACTION_TEXT);

    // ASC
    AuditEventsDto auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .sortQuery(AuditSortDto.OBJECTTYPE)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(2, auditEvents.getItems().size());

    AuditEventDto firstSortedEvent = auditEvents.getItems().get(0);
    AuditEventDto secondSortedEvent = auditEvents.getItems().get(1);

    assertEquals(AuditObjectTypeDto.CMDLET, firstSortedEvent.getObjectType());
    assertEquals(AuditObjectTypeDto.RULE, secondSortedEvent.getObjectType());

    // DESC
    auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .sortQuery(AuditSortDto._OBJECTTYPE)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(2, auditEvents.getItems().size());

    firstSortedEvent = auditEvents.getItems().get(0);
    secondSortedEvent = auditEvents.getItems().get(1);

    assertEquals(AuditObjectTypeDto.RULE, firstSortedEvent.getObjectType());
    assertEquals(AuditObjectTypeDto.CMDLET, secondSortedEvent.getObjectType());
  }

  @Test
  public void testGetAuditEventsSortByObjectId() {
    RuleDto firstRule = rulesApiClient.submitRule(RULE_TEXT);
    RuleDto secondRule = rulesApiClient.submitRule(RULE_TEXT);

    // ASC
    AuditEventsDto auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .sortQuery(AuditSortDto.OBJECTID)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(2, auditEvents.getItems().size());

    AuditEventDto firstSortedEvent = auditEvents.getItems().get(0);
    AuditEventDto secondSortedEvent = auditEvents.getItems().get(1);

    assertEquals(firstRule.getId(), firstSortedEvent.getObjectId());
    assertEquals(secondRule.getId(), secondSortedEvent.getObjectId());

    // DESC
    auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .sortQuery(AuditSortDto._OBJECTID)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(2, auditEvents.getItems().size());

    firstSortedEvent = auditEvents.getItems().get(0);
    secondSortedEvent = auditEvents.getItems().get(1);

    assertEquals(secondRule.getId(), firstSortedEvent.getObjectId());
    assertEquals(firstRule.getId(), secondSortedEvent.getObjectId());
  }

  @Test
  public void testGetAuditEventsSortByOperation() {
    RuleDto rule = rulesApiClient.submitRule(RULE_TEXT);
    rulesApiClient.startRule(rule.getId());
    rulesApiClient.stopRule(rule.getId());
    rulesApiClient.deleteRule(rule.getId());

    // ASC
    AuditEventsDto auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .sortQuery(AuditSortDto.OPERATION)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(4, auditEvents.getItems().size());

    AuditEventDto firstSortedEvent = auditEvents.getItems().get(0);
    AuditEventDto secondSortedEvent = auditEvents.getItems().get(1);
    AuditEventDto thirdSortedEvent = auditEvents.getItems().get(2);
    AuditEventDto fourthSortedEvent = auditEvents.getItems().get(3);

    assertEquals(AuditOperationDto.CREATE, firstSortedEvent.getOperation());
    assertEquals(AuditOperationDto.DELETE, secondSortedEvent.getOperation());
    assertEquals(AuditOperationDto.START, thirdSortedEvent.getOperation());
    assertEquals(AuditOperationDto.STOP, fourthSortedEvent.getOperation());

    // DESC
    auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .sortQuery(AuditSortDto._OPERATION)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(4, auditEvents.getItems().size());

    firstSortedEvent = auditEvents.getItems().get(0);
    secondSortedEvent = auditEvents.getItems().get(1);
    thirdSortedEvent = auditEvents.getItems().get(2);
    fourthSortedEvent = auditEvents.getItems().get(3);

    assertEquals(AuditOperationDto.STOP, firstSortedEvent.getOperation());
    assertEquals(AuditOperationDto.START, secondSortedEvent.getOperation());
    assertEquals(AuditOperationDto.DELETE, thirdSortedEvent.getOperation());
    assertEquals(AuditOperationDto.CREATE, fourthSortedEvent.getOperation());
  }

  @Test
  public void testGetAuditEventsSortByResult() {
    actionsApiClient.submitAction(ACTION_TEXT);
    actionsApiClient.rawClient()
        .submitAction()
        .body(new SubmitActionRequestDto().action("nonexistent"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .executeAs(Response::andReturn);

    // ASC
    AuditEventsDto auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .sortQuery(AuditSortDto.RESULT)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(2, auditEvents.getItems().size());

    AuditEventDto firstSortedEvent = auditEvents.getItems().get(0);
    AuditEventDto secondSortedEvent = auditEvents.getItems().get(1);

    assertEquals(AuditEventResultDto.FAILURE, firstSortedEvent.getResult());
    assertEquals(AuditEventResultDto.SUCCESS, secondSortedEvent.getResult());

    // DESC
    auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .sortQuery(AuditSortDto._RESULT)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(2, auditEvents.getItems().size());

    firstSortedEvent = auditEvents.getItems().get(0);
    secondSortedEvent = auditEvents.getItems().get(1);

    assertEquals(AuditEventResultDto.SUCCESS, firstSortedEvent.getResult());
    assertEquals(AuditEventResultDto.FAILURE, secondSortedEvent.getResult());
  }

  @Test
  public void testGetAuditEventsFilterByUsernameLike() {
    actionsApiClient.submitAction(ACTION_TEXT);

    AuditEventsDto auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .usernameLikeQuery("%%")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(1, auditEvents.getTotal().longValue());
    assertEquals(1, auditEvents.getItems().size());

    auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .usernameLikeQuery("nonexistent")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(0, auditEvents.getTotal().longValue());
    assertEquals(0, auditEvents.getItems().size());
  }

  @Test
  public void testGetAuditEventsFilterByEventTime() {
    long start = System.currentTimeMillis();
    ActionInfoDto action = actionsApiClient.submitAction(ACTION_TEXT);
    long end = System.currentTimeMillis();
    actionsApiClient.submitAction(ACTION_TEXT);

    AuditEventsDto auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .reqSpec(request -> request
            .addQueryParam(EventTimeIntervalDto.JSON_PROPERTY_EVENT_TIME_FROM, start)
            .addQueryParam(EventTimeIntervalDto.JSON_PROPERTY_EVENT_TIME_TO, end))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(1, auditEvents.getTotal().longValue());
    assertEquals(1, auditEvents.getItems().size());

    AuditEventDto fetchedEvent = auditEvents.getItems().get(0);
    assertEquals(action.getId(), fetchedEvent.getObjectId());
  }

  @Test
  public void testGetAuditEventsFilterByObjectTypes() {
    actionsApiClient.submitAction(ACTION_TEXT);
    rulesApiClient.submitRule(RULE_TEXT);

    AuditEventsDto auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .objectTypesQuery(AuditObjectTypeDto.RULE)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(1, auditEvents.getTotal().longValue());
    assertEquals(1, auditEvents.getItems().size());

    AuditEventDto fetchedEvent = auditEvents.getItems().get(0);
    assertEquals(AuditObjectTypeDto.RULE, fetchedEvent.getObjectType());

    auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .objectTypesQuery(AuditObjectTypeDto.CMDLET)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(1, auditEvents.getTotal().longValue());
    assertEquals(1, auditEvents.getItems().size());

    fetchedEvent = auditEvents.getItems().get(0);
    assertEquals(AuditObjectTypeDto.CMDLET, fetchedEvent.getObjectType());
  }

  @Test
  public void testGetAuditEventsFilterByObjectIds() {
    ActionInfoDto action = actionsApiClient.submitAction(ACTION_TEXT);
    rulesApiClient.submitRule(RULE_TEXT);

    AuditEventsDto auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .objectIdsQuery(action.getId())
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(1, auditEvents.getTotal().longValue());
    assertEquals(1, auditEvents.getItems().size());

    AuditEventDto fetchedEvent = auditEvents.getItems().get(0);
    assertEquals(action.getId(), fetchedEvent.getObjectId());
    assertEquals(AuditObjectTypeDto.CMDLET, fetchedEvent.getObjectType());
  }

  @Test
  public void testGetAuditEventsFilterByOperations() {
    RuleDto rule = rulesApiClient.submitRule(RULE_TEXT);
    rulesApiClient.startRule(rule.getId());
    rulesApiClient.stopRule(rule.getId());
    rulesApiClient.deleteRule(rule.getId());

    AuditEventsDto auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .operationsQuery(AuditOperationDto.CREATE)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(1, auditEvents.getTotal().longValue());
    assertEquals(1, auditEvents.getItems().size());

    AuditEventDto fetchedEvent = auditEvents.getItems().get(0);
    assertEquals(AuditOperationDto.CREATE, fetchedEvent.getOperation());

    auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .operationsQuery(AuditOperationDto.START)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(1, auditEvents.getTotal().longValue());
    assertEquals(1, auditEvents.getItems().size());

    fetchedEvent = auditEvents.getItems().get(0);
    assertEquals(AuditOperationDto.START, fetchedEvent.getOperation());

    auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .operationsQuery(AuditOperationDto.STOP)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(1, auditEvents.getTotal().longValue());
    assertEquals(1, auditEvents.getItems().size());

    fetchedEvent = auditEvents.getItems().get(0);
    assertEquals(AuditOperationDto.STOP, fetchedEvent.getOperation());

    auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .operationsQuery(AuditOperationDto.DELETE)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(1, auditEvents.getTotal().longValue());
    assertEquals(1, auditEvents.getItems().size());

    fetchedEvent = auditEvents.getItems().get(0);
    assertEquals(AuditOperationDto.DELETE, fetchedEvent.getOperation());
  }

  @Test
  public void testGetAuditEventsFilterByResults() {
    actionsApiClient.submitAction(ACTION_TEXT);
    actionsApiClient.rawClient()
        .submitAction()
        .body(new SubmitActionRequestDto().action("nonexistent"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .executeAs(Response::andReturn);

    AuditEventsDto auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .resultsQuery(AuditEventResultDto.SUCCESS)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(1, auditEvents.getTotal().longValue());
    assertEquals(1, auditEvents.getItems().size());

    AuditEventDto fetchedEvent = auditEvents.getItems().get(0);
    assertEquals(AuditEventResultDto.SUCCESS, fetchedEvent.getResult());

    auditEvents = auditApiClient.rawClient()
        .getAuditEvents()
        .resultsQuery(AuditEventResultDto.FAILURE)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(AuditEventsDto.class);

    assertEquals(1, auditEvents.getTotal().longValue());
    assertEquals(1, auditEvents.getItems().size());

    fetchedEvent = auditEvents.getItems().get(0);
    assertEquals(AuditEventResultDto.FAILURE, fetchedEvent.getResult());
  }

  @Test
  public void testGetAuditEventsPaginationWithIncorrectValue() {
    auditApiClient.rawClient()
        .getAuditEvents()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, 0))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    auditApiClient.rawClient()
        .getAuditEvents()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, -1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    auditApiClient.rawClient()
        .getAuditEvents()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, -1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    auditApiClient.rawClient()
        .getAuditEvents()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, "string"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    auditApiClient.rawClient()
        .getAuditEvents()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, "string"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
  }

  @Test
  public void testGetAuditEventsSortByIncorrectQuery() {
    auditApiClient.rawClient()
        .getAuditEvents()
        .sortQuery("nonexistent")
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
  }

  @Test
  public void testGetAuditEventsFilterByIncorrectQuery() {
    auditApiClient.rawClient()
        .getAuditEvents()
        .objectTypesQuery("nonexistent")
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    auditApiClient.rawClient()
        .getAuditEvents()
        .operationsQuery("nonexistent")
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    auditApiClient.rawClient()
        .getAuditEvents()
        .resultsQuery("nonexistent")
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
  }
}
