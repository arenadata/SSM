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
import org.smartdata.client.generated.model.ErrorResponseDto;
import org.smartdata.client.generated.model.LastActivationTimeIntervalDto;
import org.smartdata.client.generated.model.PageRequestDto;
import org.smartdata.client.generated.model.RuleDto;
import org.smartdata.client.generated.model.RuleSortDto;
import org.smartdata.client.generated.model.RuleStateDto;
import org.smartdata.client.generated.model.RulesDto;
import org.smartdata.client.generated.model.RulesInfoDto;
import org.smartdata.client.generated.model.SubmissionTimeIntervalDto;
import org.smartdata.client.generated.model.SubmitRuleRequestDto;
import org.smartdata.http.error.SsmErrorCode;
import org.smartdata.integration.api.RulesApiWrapper;

import java.time.Duration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class TestRuleRestApi extends IntegrationTestBase {

  private RulesApiWrapper apiClient;

  @Before
  public void createApi() {
    apiClient = new RulesApiWrapper();
  }

  @Test
  public void testGetRules() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";

    RuleDto rule = apiClient.submitRule(ruleText);
    RulesDto fetchedRules = apiClient.getRules();

    assertEquals(1, fetchedRules.getTotal().longValue());
    assertEquals(1, fetchedRules.getItems().size());

    RuleDto fetchedRule = fetchedRules.getItems().get(0);
    assertEquals(rule.getId(), fetchedRule.getId());
    assertEquals(rule.getState(), fetchedRule.getState());
    assertEquals(rule.getTextRepresentation(), fetchedRule.getTextRepresentation());
    assertEquals(rule.getActivationCount(), fetchedRule.getActivationCount());
    assertEquals(rule.getCmdletsGenerated(), fetchedRule.getCmdletsGenerated());
    assertEquals(rule.getLastActivationTime(), fetchedRule.getLastActivationTime());
  }

  @Test
  public void testGetRulesPagination() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";

    apiClient.submitRule(ruleText);
    RuleDto rule = apiClient.submitRule(ruleText);

    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, 1))
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, 1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    assertEquals(2, rulesDtoResponse.getTotal().longValue());
    assertEquals(1, rulesDtoResponse.getItems().size());

    RuleDto fetchedRule = rulesDtoResponse.getItems().get(0);
    assertEquals(rule.getId(), fetchedRule.getId());
  }

  @Test
  public void testGetRulesSortById() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";

    RuleDto firstRule = apiClient.submitRule(ruleText);
    RuleDto secondRule = apiClient.submitRule(ruleText);

    // ASC
    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery(RuleSortDto.ID)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    RuleDto firstSortedRule = rulesDtoResponse.getItems().get(0);
    RuleDto secondSortedRule = rulesDtoResponse.getItems().get(1);

    assertEquals(firstRule.getId(), firstSortedRule.getId());
    assertEquals(secondRule.getId(), secondSortedRule.getId());

    // DESC
    rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery(RuleSortDto._ID)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    firstSortedRule = rulesDtoResponse.getItems().get(0);
    secondSortedRule = rulesDtoResponse.getItems().get(1);

    assertEquals(secondRule.getId(), firstSortedRule.getId());
    assertEquals(firstRule.getId(), secondSortedRule.getId());
  }

  @Test
  public void testGetRulesSortBySubmitTime() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";

    RuleDto firstRule = apiClient.submitRule(ruleText);
    RuleDto secondRule = apiClient.submitRule(ruleText);

    // ASC
    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery(RuleSortDto.SUBMITTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    RuleDto firstSortedRule = rulesDtoResponse.getItems().get(0);
    RuleDto secondSortedRule = rulesDtoResponse.getItems().get(1);

    assertEquals(firstRule.getId(), firstSortedRule.getId());
    assertEquals(secondRule.getId(), secondSortedRule.getId());

    // DESC
    rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery(RuleSortDto._SUBMITTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    firstSortedRule = rulesDtoResponse.getItems().get(0);
    secondSortedRule = rulesDtoResponse.getItems().get(1);

    assertEquals(secondRule.getId(), firstSortedRule.getId());
    assertEquals(firstRule.getId(), secondSortedRule.getId());
  }

  @Test
  public void testGetRulesSortByLastActivationTime() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";

    RuleDto firstRule = apiClient.submitRule(ruleText);
    RuleDto secondRule = apiClient.submitRule(ruleText);

    apiClient.startRule(firstRule.getId());
    apiClient.startRule(secondRule.getId());

    // ASC
    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery(RuleSortDto.LASTACTIVATIONTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    RuleDto firstSortedRule = rulesDtoResponse.getItems().get(0);
    RuleDto secondSortedRule = rulesDtoResponse.getItems().get(1);

    assertEquals(firstRule.getId(), firstSortedRule.getId());
    assertEquals(secondRule.getId(), secondSortedRule.getId());

    // DESC
    rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery(RuleSortDto._LASTACTIVATIONTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    firstSortedRule = rulesDtoResponse.getItems().get(0);
    secondSortedRule = rulesDtoResponse.getItems().get(1);

    assertEquals(secondRule.getId(), firstSortedRule.getId());
    assertEquals(firstRule.getId(), secondSortedRule.getId());
  }

  @Test
  public void testGetRulesSortByActivationCount() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";

    RuleDto firstRule = apiClient.waitTillRuleTriggered(
        ruleText,
        Duration.ofMillis(250),
        Duration.ofSeconds(5));
    RuleDto secondRule = apiClient.submitRule(ruleText);


    // ASC
    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery(RuleSortDto.ACTIVATIONCOUNT)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    RuleDto firstSortedRule = rulesDtoResponse.getItems().get(0);
    RuleDto secondSortedRule = rulesDtoResponse.getItems().get(1);

    assertEquals(secondRule.getId(), firstSortedRule.getId());
    assertEquals(firstRule.getId(), secondSortedRule.getId());

    // DESC
    rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery(RuleSortDto._ACTIVATIONCOUNT)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    firstSortedRule = rulesDtoResponse.getItems().get(0);
    secondSortedRule = rulesDtoResponse.getItems().get(1);

    assertEquals(firstRule.getId(), firstSortedRule.getId());
    assertEquals(secondRule.getId(), secondSortedRule.getId());
  }

  @Test
  public void testGetRulesSortByCmdletsGenerated() {
    RuleDto firstRule = apiClient.waitTillRuleTriggered(
        "file: at now | path matches \"/*\" | sleep -ms 100",
        Duration.ofMillis(100),
        Duration.ofSeconds(2));
    RuleDto secondRule = apiClient.submitRule("file: path matches \"/tmp/test/*\" | read");

    // ASC
    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery(RuleSortDto.CMDLETSGENERATED)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    RuleDto firstSortedRule = rulesDtoResponse.getItems().get(0);
    RuleDto secondSortedRule = rulesDtoResponse.getItems().get(1);

    assertEquals(secondRule.getId(), firstSortedRule.getId());
    assertEquals(firstRule.getId(), secondSortedRule.getId());

    // DESC
    rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery(RuleSortDto._CMDLETSGENERATED)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    firstSortedRule = rulesDtoResponse.getItems().get(0);
    secondSortedRule = rulesDtoResponse.getItems().get(1);

    assertEquals(firstRule.getId(), firstSortedRule.getId());
    assertEquals(secondRule.getId(), secondSortedRule.getId());
  }

  @Test
  public void testGetRulesSortByState() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";

    RuleDto firstRule = apiClient.submitRule(ruleText);
    RuleDto secondRule = apiClient.submitRule(ruleText);

    apiClient.startRule(firstRule.getId());

    // ASC
    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery(RuleSortDto.STATE)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    RuleDto firstSortedRule = rulesDtoResponse.getItems().get(0);
    RuleDto secondSortedRule = rulesDtoResponse.getItems().get(1);

    assertEquals(firstRule.getId(), firstSortedRule.getId());
    assertEquals(secondRule.getId(), secondSortedRule.getId());

    // DESC
    rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery(RuleSortDto._STATE)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    firstSortedRule = rulesDtoResponse.getItems().get(0);
    secondSortedRule = rulesDtoResponse.getItems().get(1);

    assertEquals(secondRule.getId(), firstSortedRule.getId());
    assertEquals(firstRule.getId(), secondSortedRule.getId());
  }

  @Test
  public void testGetRulesFilterByTextRepresentationLike() {
    String firstRuleText = "file: path matches \"/tmp/test1/*\" | read";
    String secondRuleText = "file: every 5000ms | path matches \"/tmp/test2\" | read";

    apiClient.submitRule(firstRuleText);
    RuleDto secondRule = apiClient.submitRule(secondRuleText);

    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .textRepresentationLikeQuery("file: every 5000ms%")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    assertEquals(1, rulesDtoResponse.getTotal().longValue());
    assertEquals(1, rulesDtoResponse.getItems().size());

    RuleDto fetchedRule = rulesDtoResponse.getItems().get(0);
    assertEquals(secondRule.getId(), fetchedRule.getId());
    assertEquals(secondRuleText, fetchedRule.getTextRepresentation());
  }

  @Test
  public void testGetRulesFilterByTextSubmissionTime() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";
    long start = System.currentTimeMillis();
    RuleDto rule = apiClient.submitRule(ruleText);
    long end = System.currentTimeMillis();
    apiClient.submitRule(ruleText);

    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .reqSpec(request ->
            request.addQueryParam(SubmissionTimeIntervalDto.JSON_PROPERTY_SUBMISSION_TIME_FROM, start))
        .reqSpec(request ->
            request.addQueryParam(SubmissionTimeIntervalDto.JSON_PROPERTY_SUBMISSION_TIME_TO, end))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    assertEquals(1, rulesDtoResponse.getTotal().longValue());
    assertEquals(1, rulesDtoResponse.getItems().size());

    RuleDto fetchedRule = rulesDtoResponse.getItems().get(0);
    assertEquals(rule.getId(), fetchedRule.getId());
  }

  @Test
  public void testGetRulesFilterByState() {
    String ruleText = "file: path matches \"/*\" | read";
    RuleDto firstRule = apiClient.submitRule(ruleText);
    apiClient.startRule(firstRule.getId());
    RuleDto secondRule = apiClient.submitRule(ruleText);

    // ACTIVE
    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .ruleStatesQuery(RuleStateDto.ACTIVE)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    assertEquals(1, rulesDtoResponse.getTotal().longValue());
    assertEquals(1, rulesDtoResponse.getItems().size());

    RuleDto fetchedRule = rulesDtoResponse.getItems().get(0);
    assertEquals(firstRule.getId(), fetchedRule.getId());

    // DISABLED
    rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .ruleStatesQuery(RuleStateDto.DISABLED)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    assertEquals(1, rulesDtoResponse.getTotal().longValue());
    assertEquals(1, rulesDtoResponse.getItems().size());

    fetchedRule = rulesDtoResponse.getItems().get(0);
    assertEquals(secondRule.getId(), fetchedRule.getId());

    // ACTIVE+DISABLED
    rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .ruleStatesQuery(RuleStateDto.ACTIVE, RuleStateDto.DISABLED)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    assertEquals(2, rulesDtoResponse.getTotal().longValue());
    assertEquals(2, rulesDtoResponse.getItems().size());

    fetchedRule = rulesDtoResponse.getItems().get(0);
    assertEquals(firstRule.getId(), fetchedRule.getId());

    fetchedRule = rulesDtoResponse.getItems().get(1);
    assertEquals(secondRule.getId(), fetchedRule.getId());
  }

  @Test
  public void testGetRulesFilterByLastActivationTime() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";
    long start = System.currentTimeMillis();
    RuleDto rule = apiClient.submitRule(ruleText);
    apiClient.startRule(rule.getId());
    long end = System.currentTimeMillis();
    apiClient.submitRule(ruleText);

    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .reqSpec(request ->
            request.addQueryParam(LastActivationTimeIntervalDto.JSON_PROPERTY_LAST_ACTIVATION_TIME_FROM, start))
        .reqSpec(request ->
            request.addQueryParam(LastActivationTimeIntervalDto.JSON_PROPERTY_LAST_ACTIVATION_TIME_TO, end))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    assertEquals(1, rulesDtoResponse.getTotal().longValue());
    assertEquals(1, rulesDtoResponse.getItems().size());

    RuleDto fetchedRule = rulesDtoResponse.getItems().get(0);
    assertEquals(rule.getId(), fetchedRule.getId());
  }

  @Test
  public void testAddRule() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";

    RuleDto rule = apiClient.submitRule(ruleText);
    RulesDto fetchedRules = apiClient.getRules();

    assertEquals(1, fetchedRules.getTotal().longValue());
    assertEquals(1, fetchedRules.getItems().size());

    assertEquals(1, rule.getId().longValue());
    assertEquals(RuleStateDto.DISABLED, rule.getState());
    assertEquals(ruleText, rule.getTextRepresentation());
    assertEquals(0, rule.getActivationCount().longValue());
    assertEquals(0, rule.getCmdletsGenerated().longValue());
    assertNull(rule.getLastActivationTime());
  }

  @Test
  public void testGetRule() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";

    RuleDto rule = apiClient.submitRule(ruleText);
    RuleDto fetchedRule = apiClient.getRule(rule.getId());

    assertEquals(rule.getId(), fetchedRule.getId());
    assertEquals(rule.getState(), fetchedRule.getState());
    assertEquals(rule.getTextRepresentation(), fetchedRule.getTextRepresentation());
    assertEquals(rule.getActivationCount(), fetchedRule.getActivationCount());
    assertEquals(rule.getCmdletsGenerated(), fetchedRule.getCmdletsGenerated());
    assertEquals(rule.getLastActivationTime(), fetchedRule.getLastActivationTime());
  }

  @Test
  public void testStartStopRule() {
    createFile("/tmp/text1.txt");
    createFile("/tmp/text2.txt");

    String ruleText = "file: every 100ms | path matches \"/tmp/*.txt\" | read";

    RuleDto rule = apiClient.submitRule(ruleText);
    apiClient.startRule(rule.getId());
    apiClient.waitTillRuleTriggered(rule.getId(),
        Duration.ofMillis(100),
        Duration.ofSeconds(2));

    rule = apiClient.getRule(rule.getId());
    assertEquals(RuleStateDto.ACTIVE, rule.getState());
    assertTrue(rule.getActivationCount() >= 1);

    apiClient.stopRule(rule.getId());
    rule = apiClient.getRule(rule.getId());
    assertEquals(RuleStateDto.DISABLED, rule.getState());
  }

  @Test
  public void testDeleteRule() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";

    RuleDto rule = apiClient.submitRule(ruleText);
    RuleDto fetchedRule = apiClient.getRule(rule.getId());

    apiClient.deleteRule(fetchedRule.getId());

    apiClient.rawClient()
        .getRule()
        .idPath(fetchedRule.getId())
        .respSpec(response -> response.expectStatusCode(HttpStatus.NOT_FOUND_404))
        .execute(Response::andReturn);
  }

  @Test
  public void testGetRulesInfo() {
    apiClient.submitRule(
        "file: path matches \"/tmp/test1\" | read");
    RuleDto rule =
        apiClient.submitRule(
            "file: every 100ms | path matches \"/tmp/test2\" | read");

    RulesInfoDto rulesInfo = apiClient.getRulesInfo();

    assertEquals(2, rulesInfo.getTotalRules().longValue());
    assertEquals(0, rulesInfo.getActiveRules().longValue());

    apiClient.startRule(rule.getId());
    apiClient.waitTillRuleTriggered(
        rule.getId(), Duration.ofMillis(100), Duration.ofSeconds(1));

    rulesInfo = apiClient.getRulesInfo();

    assertEquals(2, rulesInfo.getTotalRules().longValue());
    assertEquals(1, rulesInfo.getActiveRules().longValue());

    apiClient.stopRule(rule.getId());
    rulesInfo = apiClient.getRulesInfo();

    assertEquals(2, rulesInfo.getTotalRules().longValue());
    assertEquals(0, rulesInfo.getActiveRules().longValue());
  }

  @Test
  public void testGetRulesPaginationWithIncorrectValue() {
    apiClient.rawClient()
        .getRules()
        .reqSpec(request -> request.addQueryParam("limit", 0))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getRules()
        .reqSpec(request -> request.addQueryParam("limit", -1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getRules()
        .reqSpec(request -> request.addQueryParam("offset", -1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getRules()
        .reqSpec(request -> request.addQueryParam("limit", "string"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getRules()
        .reqSpec(request -> request.addQueryParam("offset", "string"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
  }

  @Test
  public void testGetRulesSortByIncorrectQuery() {
    apiClient.rawClient()
        .getRules()
        .sortQuery("nonexistent")
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
  }

  @Test
  public void testGetRulesFilterByIncorrectRuleState() {
    apiClient.rawClient()
        .getRules()
        .ruleStatesQuery("NONEXISTENT")
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
  }

  @Test
  public void testAddIncorrectRule() {
    apiClient.rawClient()
        .addRule()
        .body(new SubmitRuleRequestDto().rule("INCORRECT_RULE"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .executeAs(Response::andReturn);
  }

  @Test
  public void testDeleteNotFoundIdRule() {
    apiClient.rawClient()
        .deleteRule()
        .idPath(777)
        .respSpec(response -> response.expectStatusCode(HttpStatus.NOT_FOUND_404))
        .execute(Response::andReturn);
  }

  @Test
  public void testGetNotFoundIdRule() {
    apiClient.rawClient()
        .getRule()
        .idPath(777)
        .respSpec(response -> response.expectStatusCode(HttpStatus.NOT_FOUND_404))
        .execute(Response::andReturn);
  }

  @Test
  public void testStartNotFoundIdRule() {
    apiClient.rawClient()
        .startRule()
        .idPath(777)
        .respSpec(response -> response.expectStatusCode(HttpStatus.NOT_FOUND_404))
        .execute(Response::andReturn);
  }

  @Test
  public void testStopNotFoundIdRule() {
    apiClient.rawClient()
        .stopRule()
        .idPath(777)
        .respSpec(response -> response.expectStatusCode(HttpStatus.NOT_FOUND_404))
        .execute(Response::andReturn);
  }

  @Test
  public void testThrowStateTransitionError() {
    createFile("/tmp/text1.txt");

    RuleDto rule = apiClient.waitTillRuleTriggered(
        "file: at now | path matches \"/tmp/*.txt\" | read",
        Duration.ofMillis(100),
        Duration.ofSeconds(2));

    ErrorResponseDto errorDto = apiClient.rawClient()
        .startRule()
        .idPath(rule.getId())
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::body)
        .as(ErrorResponseDto.class);

    assertEquals(SsmErrorCode.STATE_TRANSITION_ERROR.getCode(), errorDto.getCode());
    assertEquals(
        "Rule state transition is not supported: FINISHED -> ACTIVE",
        errorDto.getMessage());
  }
}
