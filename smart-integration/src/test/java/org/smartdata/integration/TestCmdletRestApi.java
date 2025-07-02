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
import org.junit.Ignore;
import org.junit.Test;
import org.smartdata.client.generated.model.CmdletDto;
import org.smartdata.client.generated.model.CmdletSortDto;
import org.smartdata.client.generated.model.CmdletStateDto;
import org.smartdata.client.generated.model.CmdletsDto;
import org.smartdata.client.generated.model.ErrorResponseDto;
import org.smartdata.client.generated.model.PageRequestDto;
import org.smartdata.client.generated.model.RuleDto;
import org.smartdata.client.generated.model.StateChangeTimeIntervalDto;
import org.smartdata.client.generated.model.SubmissionTimeIntervalDto;
import org.smartdata.client.generated.model.SubmitCmdletRequestDto;
import org.smartdata.integration.api.CmdletsApiWrapper;
import org.smartdata.integration.api.RulesApiWrapper;

import java.time.Duration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestCmdletRestApi extends IntegrationTestBase {

  private CmdletsApiWrapper apiClient;
  private RulesApiWrapper rulesApiClient;

  private static final String CMDLET_TEXT = "read -file /tmp/text.txt; delete -file /tmp/text.txt";
  private static final String RULE_TEXT = "file: at now | path matches \"/*\" | sleep -ms 100";
  private static final String FILE_PATH = "/tmp/text.txt";

  @Before
  public void createApi() {
    apiClient = new CmdletsApiWrapper();
    rulesApiClient = new RulesApiWrapper();
  }

  @Test
  public void testSubmitGetCmdlet() {
    createFile(FILE_PATH);

    CmdletDto createdCmdlet = apiClient.submitCmdlet(CMDLET_TEXT);

    CmdletDto fetchedCmdlet = apiClient.waitTillCmdletFinished(
        createdCmdlet.getId(), Duration.ofMillis(100L), Duration.ofSeconds(1L));

    assertEquals(fetchedCmdlet.getId(), createdCmdlet.getId());
    assertEquals(CMDLET_TEXT, fetchedCmdlet.getTextRepresentation());
    assertEquals(2, fetchedCmdlet.getActionIds().size());
    assertEquals(CmdletStateDto.DONE, fetchedCmdlet.getState());
  }

  @Test
  public void testSubmitGetCmdlets() {
    createFile(FILE_PATH);

    CmdletDto createdCmdlet = apiClient.submitCmdlet(CMDLET_TEXT);

    // we have to wait a bit, because of async cmdlets transfer
    // from in-memory cache to metastore
    waitCmdletsTotal(1);

    CmdletsDto fetchedCmdlets = apiClient.getCmdlets();

    assertEquals(1L, fetchedCmdlets.getItems().size());
    CmdletDto fetchedCmdlet = fetchedCmdlets.getItems().get(0);
    assertEquals(createdCmdlet.getId(), fetchedCmdlet.getId());
    assertEquals(CMDLET_TEXT, fetchedCmdlet.getTextRepresentation());
  }

  @Test
  public void testDeleteCmdlet() {
    createFile(FILE_PATH);

    String cmdletText = "sleep -ms 10000; read -file /tmp/text1.txt";
    CmdletDto createdCmdlet = apiClient.submitCmdlet(cmdletText);

    CmdletDto cmdlet = apiClient.getCmdlet(createdCmdlet.getId());

    assertEquals(createdCmdlet.getId(), cmdlet.getId());

    apiClient.deleteCmdlet(createdCmdlet.getId());

    // we have to wait a bit, because of async removal of cmdlet from in-memory cache
    retryUntil(
        () -> apiClient.rawClient()
            .getCmdlet()
            .idPath(createdCmdlet.getId())
            .execute(Response::andReturn),
        response -> response.getStatusCode() == HttpStatus.NOT_FOUND_404,
        Duration.ofMillis(100),
        Duration.ofSeconds(30)
    );
  }

  @Test
  public void testReturnNotFoundOnUnknownId() {
    apiClient.rawClient()
        .getCmdlet()
        .idPath(777)
        .respSpec(response -> response.expectStatusCode(HttpStatus.NOT_FOUND_404))
        .execute(Response::andReturn);
  }

  @Test
  public void testGetCmdletsPagination() {
    apiClient.submitCmdlet(CMDLET_TEXT);
    CmdletDto cmdlet = apiClient.submitCmdlet(CMDLET_TEXT);

    waitCmdletsTotal(2);

    CmdletsDto cmdlets = apiClient.rawClient()
        .getCmdlets()
        .reqSpec(request -> request
            .addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, 1)
            .addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, 1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CmdletsDto.class);

    assertEquals(2, cmdlets.getTotal().longValue());
    assertEquals(1, cmdlets.getItems().size());

    CmdletDto fetchedCmdlet = cmdlets.getItems().get(0);
    assertEquals(cmdlet.getId(), fetchedCmdlet.getId());
  }

  @Test
  public void testGetCmdletsSortById() {
    CmdletDto firstCmdlet = apiClient.submitCmdlet(CMDLET_TEXT);
    CmdletDto secondCmdlet = apiClient.submitCmdlet(CMDLET_TEXT);

    waitCmdletsTotal(2);

    // ASC
    CmdletsDto cmdlets = apiClient.rawClient()
        .getCmdlets()
        .sortQuery(CmdletSortDto.ID)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CmdletsDto.class);

    assertEquals(2, cmdlets.getTotal().longValue());
    assertEquals(2, cmdlets.getItems().size());

    CmdletDto firstSortedCmdlet = cmdlets.getItems().get(0);
    CmdletDto secondSortedCmdlet = cmdlets.getItems().get(1);

    assertEquals(firstCmdlet.getId(), firstSortedCmdlet.getId());
    assertEquals(secondCmdlet.getId(), secondSortedCmdlet.getId());

    // DESC
    cmdlets = apiClient.rawClient()
        .getCmdlets()
        .sortQuery(CmdletSortDto._ID)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CmdletsDto.class);

    assertEquals(2, cmdlets.getTotal().longValue());
    assertEquals(2, cmdlets.getItems().size());

    firstSortedCmdlet = cmdlets.getItems().get(0);
    secondSortedCmdlet = cmdlets.getItems().get(1);

    assertEquals(secondCmdlet.getId(), firstSortedCmdlet.getId());
    assertEquals(firstCmdlet.getId(), secondSortedCmdlet.getId());
  }

  @Test
  public void testGetCmdletsSortByRuleId() {
    RuleDto firstRule = rulesApiClient.waitTillRuleTriggered(
        RULE_TEXT, Duration.ofMillis(100), Duration.ofSeconds(5));
    RuleDto secondRule = rulesApiClient.waitTillRuleTriggered(
        RULE_TEXT, Duration.ofMillis(100), Duration.ofSeconds(5));

    waitCmdletsTotal(2);

    // ASC
    CmdletsDto cmdlets = apiClient.rawClient()
        .getCmdlets()
        .sortQuery(CmdletSortDto.RULEID)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CmdletsDto.class);

    assertEquals(2, cmdlets.getTotal().longValue());
    assertEquals(2, cmdlets.getItems().size());

    CmdletDto firstSortedCmdlet = cmdlets.getItems().get(0);
    CmdletDto secondSortedCmdlet = cmdlets.getItems().get(1);

    assertEquals(firstRule.getId(), firstSortedCmdlet.getRuleId());
    assertEquals(secondRule.getId(), secondSortedCmdlet.getRuleId());

    // DESC
    cmdlets = apiClient.rawClient()
        .getCmdlets()
        .sortQuery(CmdletSortDto._RULEID)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CmdletsDto.class);

    assertEquals(2, cmdlets.getTotal().longValue());
    assertEquals(2, cmdlets.getItems().size());

    firstSortedCmdlet = cmdlets.getItems().get(0);
    secondSortedCmdlet = cmdlets.getItems().get(1);

    assertEquals(secondRule.getId(), firstSortedCmdlet.getRuleId());
    assertEquals(firstRule.getId(), secondSortedCmdlet.getRuleId());
  }

  @Test
  public void testGetCmdletsSortByState() {
    apiClient.waitTillCmdletFinished(CMDLET_TEXT, Duration.ofMillis(100), Duration.ofSeconds(5));
    apiClient.waitTillCmdletFinished("sleep -ms 10", Duration.ofMillis(100), Duration.ofSeconds(5));

    waitCmdletsTotal(2);

    // ASC
    CmdletsDto cmdlets = apiClient.rawClient()
        .getCmdlets()
        .sortQuery(CmdletSortDto.STATE)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CmdletsDto.class);

    assertEquals(2, cmdlets.getTotal().longValue());
    assertEquals(2, cmdlets.getItems().size());

    CmdletDto firstSortedCmdlet = cmdlets.getItems().get(0);
    CmdletDto secondSortedCmdlet = cmdlets.getItems().get(1);

    assertEquals(CmdletStateDto.FAILED, firstSortedCmdlet.getState());
    assertEquals(CmdletStateDto.DONE, secondSortedCmdlet.getState());

    // DESC
    cmdlets = apiClient.rawClient()
        .getCmdlets()
        .sortQuery(CmdletSortDto._STATE)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CmdletsDto.class);

    assertEquals(2, cmdlets.getTotal().longValue());
    assertEquals(2, cmdlets.getItems().size());

    firstSortedCmdlet = cmdlets.getItems().get(0);
    secondSortedCmdlet = cmdlets.getItems().get(1);

    assertEquals(CmdletStateDto.DONE, firstSortedCmdlet.getState());
    assertEquals(CmdletStateDto.FAILED, secondSortedCmdlet.getState());
  }

  @Test
  public void testGetCmdletsSortBySubmissionTime() {
    CmdletDto firstCmdlet = apiClient.submitCmdlet(CMDLET_TEXT);
    CmdletDto secondCmdlet = apiClient.submitCmdlet(CMDLET_TEXT);

    waitCmdletsTotal(2);

    // ASC
    CmdletsDto cmdlets = apiClient.rawClient()
        .getCmdlets()
        .sortQuery(CmdletSortDto.SUBMISSIONTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CmdletsDto.class);

    assertEquals(2, cmdlets.getTotal().longValue());
    assertEquals(2, cmdlets.getItems().size());

    CmdletDto firstSortedCmdlet = cmdlets.getItems().get(0);
    CmdletDto secondSortedCmdlet = cmdlets.getItems().get(1);

    assertEquals(firstCmdlet.getId(), firstSortedCmdlet.getId());
    assertEquals(secondCmdlet.getId(), secondSortedCmdlet.getId());

    // DESC
    cmdlets = apiClient.rawClient()
        .getCmdlets()
        .sortQuery(CmdletSortDto._SUBMISSIONTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CmdletsDto.class);

    assertEquals(2, cmdlets.getTotal().longValue());
    assertEquals(2, cmdlets.getItems().size());

    firstSortedCmdlet = cmdlets.getItems().get(0);
    secondSortedCmdlet = cmdlets.getItems().get(1);

    assertEquals(secondCmdlet.getId(), firstSortedCmdlet.getId());
    assertEquals(firstCmdlet.getId(), secondSortedCmdlet.getId());
  }

  @Test
  public void testGetCmdletsSortByStateChangedTime() {
    CmdletDto firstCmdlet =
        apiClient.waitTillCmdletFinished(CMDLET_TEXT, Duration.ofMillis(100), Duration.ofSeconds(5));
    CmdletDto secondCmdlet =
        apiClient.waitTillCmdletFinished(CMDLET_TEXT, Duration.ofMillis(100), Duration.ofSeconds(5));

    waitCmdletsTotal(2);

    // ASC
    CmdletsDto cmdlets = apiClient.rawClient()
        .getCmdlets()
        .sortQuery(CmdletSortDto.STATECHANGEDTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CmdletsDto.class);

    assertEquals(2, cmdlets.getTotal().longValue());
    assertEquals(2, cmdlets.getItems().size());

    CmdletDto firstSortedCmdlet = cmdlets.getItems().get(0);
    CmdletDto secondSortedCmdlet = cmdlets.getItems().get(1);

    assertEquals(firstCmdlet.getId(), firstSortedCmdlet.getId());
    assertEquals(secondCmdlet.getId(), secondSortedCmdlet.getId());

    // DESC
    cmdlets = apiClient.rawClient()
        .getCmdlets()
        .sortQuery(CmdletSortDto._STATECHANGEDTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CmdletsDto.class);

    assertEquals(2, cmdlets.getTotal().longValue());
    assertEquals(2, cmdlets.getItems().size());

    firstSortedCmdlet = cmdlets.getItems().get(0);
    secondSortedCmdlet = cmdlets.getItems().get(1);

    assertEquals(secondCmdlet.getId(), firstSortedCmdlet.getId());
    assertEquals(firstCmdlet.getId(), secondSortedCmdlet.getId());
  }

  @Test
  public void testGetCmdletsFilterByTextRepresentationLike() {
    String cmdletText = "sleep -ms 10";
    apiClient.submitCmdlet(CMDLET_TEXT);
    CmdletDto secondCmdlet = apiClient.submitCmdlet(cmdletText);

    waitCmdletsTotal(2);

    CmdletsDto cmdlets = apiClient.rawClient()
        .getCmdlets()
        .textRepresentationLikeQuery("sleep -ms%")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CmdletsDto.class);

    assertEquals(1, cmdlets.getTotal().longValue());
    assertEquals(1, cmdlets.getItems().size());

    CmdletDto fetchedCmdlet = cmdlets.getItems().get(0);
    assertEquals(secondCmdlet.getId(), fetchedCmdlet.getId());
    assertEquals(cmdletText, fetchedCmdlet.getTextRepresentation());
  }

  @Test
  public void testGetCmdletsFilterBySubmissionTime() {
    long start = System.currentTimeMillis();
    CmdletDto cmdlet = apiClient.submitCmdlet(CMDLET_TEXT);
    long end = System.currentTimeMillis();
    apiClient.submitCmdlet(CMDLET_TEXT);

    waitCmdletsTotal(2);

    CmdletsDto cmdlets = apiClient.rawClient()
        .getCmdlets()
        .reqSpec(request -> request
            .addQueryParam(SubmissionTimeIntervalDto.JSON_PROPERTY_SUBMISSION_TIME_FROM, start)
            .addQueryParam(SubmissionTimeIntervalDto.JSON_PROPERTY_SUBMISSION_TIME_TO, end))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CmdletsDto.class);

    assertEquals(1, cmdlets.getTotal().longValue());
    assertEquals(1, cmdlets.getItems().size());

    CmdletDto fetchedCmdlet = cmdlets.getItems().get(0);
    assertEquals(cmdlet.getId(), fetchedCmdlet.getId());
  }

  @Test
  public void testGetCmdletsFilterByRulesIds() {
    RuleDto rule = rulesApiClient.waitTillRuleTriggered(RULE_TEXT, Duration.ofMillis(100), Duration.ofSeconds(5));
    rulesApiClient.waitTillRuleTriggered(RULE_TEXT, Duration.ofMillis(100), Duration.ofSeconds(5));

    waitCmdletsTotal(2);

    CmdletsDto cmdlets = apiClient.rawClient()
        .getCmdlets()
        .ruleIdsQuery(rule.getId())
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CmdletsDto.class);

    assertEquals(1, cmdlets.getTotal().longValue());
    assertEquals(1, cmdlets.getItems().size());

    CmdletDto fetchedCmdlet = cmdlets.getItems().get(0);
    assertEquals(rule.getId(), fetchedCmdlet.getRuleId());
  }

  @Test
  public void testGetCmdletsFilterByStates() {
    CmdletDto cmdlet = apiClient.waitTillCmdletFinished(CMDLET_TEXT, Duration.ofMillis(100), Duration.ofSeconds(5));
    apiClient.waitTillCmdletFinished("sleep -ms 10", Duration.ofMillis(100), Duration.ofSeconds(5));

    waitCmdletsTotal(2);

    CmdletsDto cmdlets = apiClient.rawClient()
        .getCmdlets()
        .statesQuery(CmdletStateDto.FAILED)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CmdletsDto.class);

    assertEquals(1, cmdlets.getTotal().longValue());
    assertEquals(1, cmdlets.getItems().size());

    CmdletDto fetchedCmdlet = cmdlets.getItems().get(0);
    assertEquals(cmdlet.getId(), fetchedCmdlet.getId());
  }

  @Test
  public void testGetCmdletsFilterByStateChangedTime() {
    long start = System.currentTimeMillis();
    CmdletDto cmdlet = apiClient.waitTillCmdletFinished(CMDLET_TEXT, Duration.ofMillis(100), Duration.ofSeconds(5));
    long end = System.currentTimeMillis();
    apiClient.waitTillCmdletFinished(CMDLET_TEXT, Duration.ofMillis(100), Duration.ofSeconds(5));

    waitCmdletsTotal(2);

    CmdletsDto cmdlets = apiClient.rawClient()
        .getCmdlets()
        .reqSpec(request -> request
            .addQueryParam(StateChangeTimeIntervalDto.JSON_PROPERTY_STATE_CHANGED_TIME_FROM, start)
            .addQueryParam(StateChangeTimeIntervalDto.JSON_PROPERTY_STATE_CHANGED_TIME_TO, end))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CmdletsDto.class);

    assertEquals(1, cmdlets.getTotal().longValue());
    assertEquals(1, cmdlets.getItems().size());

    CmdletDto fetchedCmdlet = cmdlets.getItems().get(0);
    assertEquals(cmdlet.getId(), fetchedCmdlet.getId());
  }

  @Test
  @Ignore("Cmdlet returns to the state before stopping")
  public void testStopCmdlet() {
    CmdletDto cmdlet = apiClient.submitCmdlet("sleep -ms 30000");
    apiClient.stopCmdlet(cmdlet.getId());
    CmdletDto stopedCmdlet = apiClient.getCmdlet(cmdlet.getId());
    assertEquals(CmdletStateDto.DISABLED, stopedCmdlet.getState());
  }

  @Test
  public void testGetCmdletsPaginationWithIncorrectValue() {
    ErrorResponseDto errorResponse = apiClient.rawClient()
        .getCmdlets()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, 0))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertEquals("must be greater than or equal to 1", errorResponse.getMessage());

    errorResponse = apiClient.rawClient()
        .getCmdlets()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, -1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertEquals("must be greater than or equal to 1", errorResponse.getMessage());

    errorResponse = apiClient.rawClient()
        .getCmdlets()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, -1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertEquals("must be greater than or equal to 0", errorResponse.getMessage());

    errorResponse = apiClient.rawClient()
        .getCmdlets()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, "string"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertTrue(errorResponse.getMessage().contains("Failed to convert property value of type"));

    errorResponse = apiClient.rawClient()
        .getCmdlets()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, "string"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertTrue(errorResponse.getMessage().contains("Failed to convert property value of type"));
  }

  @Test
  public void testGetCmdletsSortByIncorrectQuery() {
    ErrorResponseDto errorResponse = apiClient.rawClient()
        .getCmdlets()
        .sortQuery("nonexistent")
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertTrue(errorResponse.getMessage().contains("Failed to convert value of type"));
    assertTrue(errorResponse.getMessage().contains("Unexpected value 'nonexistent'"));
  }

  @Test
  public void testGetCmdletsFilterByIncorrectQuery() {
    ErrorResponseDto errorResponse = apiClient.rawClient()
        .getCmdlets()
        .statesQuery("nonexistent")
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertTrue(errorResponse.getMessage().contains("Failed to convert value of type"));
    assertTrue(errorResponse.getMessage().contains("Unexpected value 'nonexistent'"));


    errorResponse = apiClient.rawClient()
        .getCmdlets()
        .ruleIdsQuery("nonexistent")
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertTrue(errorResponse.getMessage().contains("Failed to convert value of type"));
    assertTrue(errorResponse.getMessage().contains("For input string: \"nonexistent\""));
  }

  @Test
  public void testAddIncorrectCmdlet() {
    ErrorResponseDto errorResponse = apiClient.rawClient()
        .addCmdlet()
        .body(new SubmitCmdletRequestDto().cmdlet("INCORRECT_CMDLET"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertEquals("Error parsing cmdlet: INCORRECT_CMDLET. Unknown actions used in cmdlet: [INCORRECT_CMDLET]",
        errorResponse.getMessage());
  }

  @Test
  public void testDeleteNotFoundIdCmdlet() {
    apiClient.rawClient()
        .deleteCmdlet()
        .idPath(777)
        .respSpec(response -> response.expectStatusCode(HttpStatus.NOT_FOUND_404))
        .execute(Response::andReturn);
  }

  @Test
  public void testStopNotFoundIdCmdlet() {
    apiClient.rawClient()
        .stopCmdlet()
        .idPath(777)
        .respSpec(response -> response.expectStatusCode(HttpStatus.NOT_FOUND_404))
        .execute(Response::andReturn);
  }

  private void waitCmdletsTotal(long total) {
    retryUntil(
        () -> apiClient.getCmdlets(),
        cmdlets -> cmdlets.getTotal() == total,
        Duration.ofMillis(100),
        Duration.ofSeconds(5)
    );
  }
}
