/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
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
import org.smartdata.client.generated.model.PageRequestDto;
import org.smartdata.client.generated.model.RuleDto;
import org.smartdata.client.generated.model.RuleStateDto;
import org.smartdata.client.generated.model.RulesDto;
import org.smartdata.client.generated.model.RulesInfoDto;
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
    String ruleText1 = "file: path matches \"/tmp/test1/*\" | read";
    String ruleText2 = "file: path matches \"/tmp/test2/*\" | read";

    apiClient.submitRule(ruleText1);
    apiClient.submitRule(ruleText2);

    // TODO Wrong params
    PageRequestDto pageRequestDto = new PageRequestDto().limit(1).offset(1L);

    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .reqSpec(requestSpecBuilder -> requestSpecBuilder.addQueryParam("limit", 1))
        .reqSpec(requestSpecBuilder -> requestSpecBuilder.addQueryParam("offset", 1))
//        .pageRequestQuery(pageRequestDto)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    assertEquals(2, rulesDtoResponse.getTotal().longValue());
    assertEquals(1, rulesDtoResponse.getItems().size());

    RuleDto ruleDto = rulesDtoResponse.getItems().get(0);
    assertEquals(2, ruleDto.getId().longValue());
    assertEquals(ruleText2, ruleDto.getTextRepresentation());
  }

  @Test
  public void testGetRulesSortById() {
    String ruleText1 = "file: path matches \"/tmp/test1/*\" | read";
    String ruleText2 = "file: path matches \"/tmp/test2/*\" | read";

    apiClient.submitRule(ruleText1);
    apiClient.submitRule(ruleText2);

    // ASC
    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery("id")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    RuleDto firstRule = rulesDtoResponse.getItems().get(0);
    RuleDto secondRule = rulesDtoResponse.getItems().get(1);

    assertEquals(1, firstRule.getId().longValue());
    assertEquals(2, secondRule.getId().longValue());

    // DESC
    rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery("-id")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    firstRule = rulesDtoResponse.getItems().get(0);
    secondRule = rulesDtoResponse.getItems().get(1);

    assertEquals(2, firstRule.getId().longValue());
    assertEquals(1, secondRule.getId().longValue());
  }

  @Test
  public void testGetRulesSortBySubmitTime() {
    String ruleText1 = "file: path matches \"/tmp/test1/*\" | read";
    String ruleText2 = "file: path matches \"/tmp/test2/*\" | read";

    apiClient.submitRule(ruleText1);
    apiClient.submitRule(ruleText2);

    // ASC
    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery("submitTime")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    RuleDto firstRule = rulesDtoResponse.getItems().get(0);
    RuleDto secondRule = rulesDtoResponse.getItems().get(1);

    assertEquals(1, firstRule.getId().longValue());
    assertEquals(2, secondRule.getId().longValue());

    // DESC
    rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery("-submitTime")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    firstRule = rulesDtoResponse.getItems().get(0);
    secondRule = rulesDtoResponse.getItems().get(1);

    assertEquals(2, firstRule.getId().longValue());
    assertEquals(1, secondRule.getId().longValue());
  }

  @Test
  public void testGetRulesSortByLastActivationTime() {
    String ruleText1 = "file: path matches \"/tmp/test1/*\" | read";
    String ruleText2 = "file: path matches \"/tmp/test2/*\" | read";

    RuleDto ruleDto1 = apiClient.submitRule(ruleText1);
    RuleDto ruleDto2 = apiClient.submitRule(ruleText2);

    apiClient.startRule(ruleDto1.getId());
    apiClient.startRule(ruleDto2.getId());

    // ASC
    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery("lastActivationTime")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    RuleDto firstRule = rulesDtoResponse.getItems().get(0);
    RuleDto secondRule = rulesDtoResponse.getItems().get(1);

    assertEquals(1, firstRule.getId().longValue());
    assertEquals(2, secondRule.getId().longValue());

    // DESC
    rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery("-lastActivationTime")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    firstRule = rulesDtoResponse.getItems().get(0);
    secondRule = rulesDtoResponse.getItems().get(1);

    assertEquals(2, firstRule.getId().longValue());
    assertEquals(1, secondRule.getId().longValue());
  }

  @Test
  public void testGetRulesSortByActivationCount() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";

    RuleDto ruleDto1 = apiClient.waitTillRuleTriggered(
        ruleText,
        Duration.ofMillis(250),
        Duration.ofSeconds(5));
    RuleDto ruleDto2 = apiClient.submitRule(ruleText);


    // ASC
    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery("activationCount")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    RuleDto firstRule = rulesDtoResponse.getItems().get(0);
    RuleDto secondRule = rulesDtoResponse.getItems().get(1);

    assertEquals(2, firstRule.getId().longValue());
    assertEquals(1, secondRule.getId().longValue());

    // DESC
    rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery("-activationCount")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    firstRule = rulesDtoResponse.getItems().get(0);
    secondRule = rulesDtoResponse.getItems().get(1);

    assertEquals(1, firstRule.getId().longValue());
    assertEquals(2, secondRule.getId().longValue());
  }

  @Test
  public void testGetRulesSortByCmdletsGenerated() {
    createFile("/tmp/text1.txt");

    RuleDto rule1 = apiClient.waitTillRuleTriggered(
        "file: at now | path matches \"/tmp/*.txt\" | read",
        Duration.ofMillis(100),
        Duration.ofSeconds(2));

    String ruleText = "file: path matches \"/tmp/test/*\" | read";
    RuleDto rule2 = apiClient.submitRule(ruleText);


    // ASC
    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery("cmdletsGenerated")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    RuleDto firstRule = rulesDtoResponse.getItems().get(0);
    RuleDto secondRule = rulesDtoResponse.getItems().get(1);

    assertEquals(2, firstRule.getId().longValue());
    assertEquals(1, secondRule.getId().longValue());

    // DESC
    rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery("-cmdletsGenerated")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    firstRule = rulesDtoResponse.getItems().get(0);
    secondRule = rulesDtoResponse.getItems().get(1);

    assertEquals(1, firstRule.getId().longValue());
    assertEquals(2, secondRule.getId().longValue());
  }

  @Test
  public void testGetRulesSortBySort() {
    String ruleText1 = "file: path matches \"/tmp/test1/*\" | read";
    String ruleText2 = "file: path matches \"/tmp/test2/*\" | read";

    RuleDto ruleDto1 = apiClient.submitRule(ruleText1);
    RuleDto ruleDto2 = apiClient.submitRule(ruleText2);

    apiClient.startRule(ruleDto1.getId());


    // ASC
    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery("state")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    RuleDto firstRule = rulesDtoResponse.getItems().get(0);
    RuleDto secondRule = rulesDtoResponse.getItems().get(1);

    assertEquals(1, firstRule.getId().longValue());
    assertEquals(2, secondRule.getId().longValue());

    // DESC
    rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .sortQuery("-state")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    firstRule = rulesDtoResponse.getItems().get(0);
    secondRule = rulesDtoResponse.getItems().get(1);

    assertEquals(2, firstRule.getId().longValue());
    assertEquals(1, secondRule.getId().longValue());
  }

  @Test
  public void testGetRulesFilterByTextRepresentationLike() {
    String ruleText1 = "file: path matches \"/tmp/test1/*\" | read";
    String ruleText2 = "file: every 5000ms | path matches \"/tmp/test2\" | read";

    apiClient.submitRule(ruleText1);
    apiClient.submitRule(ruleText2);

    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .textRepresentationLikeQuery("file: every 5000ms%")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    assertEquals(1, rulesDtoResponse.getTotal().longValue());
    assertEquals(1, rulesDtoResponse.getItems().size());

    RuleDto rule = rulesDtoResponse.getItems().get(0);
    assertEquals(2, rule.getId().longValue());
    assertEquals(ruleText2, rule.getTextRepresentation());
  }

  @Test
  public void testGetRulesFilterByTextSubmissionTime() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";
    long start = System.currentTimeMillis();
    apiClient.submitRule(ruleText);
    long end = System.currentTimeMillis();
    apiClient.submitRule(ruleText);
    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .reqSpec(requestSpecBuilder -> requestSpecBuilder.addQueryParam("submissionTimeFrom", start))
        .reqSpec(requestSpecBuilder -> requestSpecBuilder.addQueryParam("submissionTimeTo", end))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    assertEquals(1, rulesDtoResponse.getTotal().longValue());
    assertEquals(1, rulesDtoResponse.getItems().size());

    RuleDto rule = rulesDtoResponse.getItems().get(0);
    assertEquals(1, rule.getId().longValue());
  }

  @Test
  public void testGetRulesFilterByRuleStates() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";
    RuleDto rule1 = apiClient.submitRule(ruleText);
    apiClient.startRule(rule1.getId());
    RuleDto rule2 = apiClient.submitRule(ruleText);

    // ACTIVE
    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .ruleStatesQuery(RuleStateDto.ACTIVE)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    assertEquals(1, rulesDtoResponse.getTotal().longValue());
    assertEquals(1, rulesDtoResponse.getItems().size());

    RuleDto rule = rulesDtoResponse.getItems().get(0);
    assertEquals(1, rule.getId().longValue());

    // DISABLED
    rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .ruleStatesQuery(RuleStateDto.DISABLED)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    assertEquals(1, rulesDtoResponse.getTotal().longValue());
    assertEquals(1, rulesDtoResponse.getItems().size());

    rule = rulesDtoResponse.getItems().get(0);
    assertEquals(2, rule.getId().longValue());

    // ACTIVE+DISABLED
    rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .ruleStatesQuery(RuleStateDto.ACTIVE, RuleStateDto.DISABLED)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    assertEquals(2, rulesDtoResponse.getTotal().longValue());
    assertEquals(2, rulesDtoResponse.getItems().size());

    rule1 = rulesDtoResponse.getItems().get(0);
    rule2 = rulesDtoResponse.getItems().get(1);
    assertEquals(1, rule1.getId().longValue());
    assertEquals(2, rule2.getId().longValue());
  }

  @Test
  public void testGetRulesFilterByLastActivationTime() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";
    long start = System.currentTimeMillis();
    RuleDto ruleDto = apiClient.submitRule(ruleText);
    apiClient.startRule(ruleDto.getId());
    long end = System.currentTimeMillis();
    apiClient.submitRule(ruleText);
    RulesDto rulesDtoResponse = apiClient.rawClient()
        .getRules()
        .reqSpec(requestSpecBuilder -> requestSpecBuilder.addQueryParam("lastActivationTimeFrom", start))
        .reqSpec(requestSpecBuilder -> requestSpecBuilder.addQueryParam("lastActivationTimeTo", end))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(RulesDto.class);

    assertEquals(1, rulesDtoResponse.getTotal().longValue());
    assertEquals(1, rulesDtoResponse.getItems().size());

    RuleDto rule = rulesDtoResponse.getItems().get(0);
    assertEquals(1, rule.getId().longValue());
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

  /*
  Negative
   */

  @Test
  public void testNegativeGetRulesPagination() {
    apiClient.rawClient()
        .getRules()
        .reqSpec(requestSpecBuilder -> requestSpecBuilder.addQueryParam("limit", 0))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getRules()
        .reqSpec(requestSpecBuilder -> requestSpecBuilder.addQueryParam("limit", -1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getRules()
        .reqSpec(requestSpecBuilder -> requestSpecBuilder.addQueryParam("offset", -1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getRules()
        .reqSpec(requestSpecBuilder -> requestSpecBuilder.addQueryParam("limit", "string"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getRules()
        .reqSpec(requestSpecBuilder -> requestSpecBuilder.addQueryParam("offset", "string"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
  }

  @Test
  public void testNegativeGetRulesSort() {
    apiClient.rawClient()
        .getRules()
        .sortQuery("nonexistent")
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
  }

  @Test
  public void testNegativeGetRulesFilterByTextSubmissionTime() {
    // TODO status 200 when timeFrom later than timeTo
    long start = System.currentTimeMillis();
    long end = start + 1000000;

    apiClient.rawClient()
        .getRules()
        .reqSpec(requestSpecBuilder -> requestSpecBuilder.addQueryParam("submissionTimeFrom", end))
        .reqSpec(requestSpecBuilder -> requestSpecBuilder.addQueryParam("submissionTimeTo", start))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
  }

  @Test
  public void testNegativeGetRulesFilterByRuleStates() {
    apiClient.rawClient()
        .getRules()
        .ruleStatesQuery("NONEXISTENT")
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
  }

  @Test
  public void testNegativeGetRulesFilterByLastActivationTime() {
    // TODO status 200 when timeFrom later than timeTo
    long start = System.currentTimeMillis();
    long end = start + 1000000;

    apiClient.rawClient()
        .getRules()
        .reqSpec(requestSpecBuilder -> requestSpecBuilder.addQueryParam("lastActivationTimeFrom", end))
        .reqSpec(requestSpecBuilder -> requestSpecBuilder.addQueryParam("lastActivationTimeTo", start))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
  }

  @Test
  public void testNegativeAddRule() {
    apiClient.rawClient()
        .addRule()
        .body(new SubmitRuleRequestDto().rule("INCORRECT_RULE"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .executeAs(Response::andReturn);
  }

  @Test
  public void testNegativeDeleteRule() {
    apiClient.rawClient()
        .deleteRule()
        .idPath(777)
        .respSpec(response -> response.expectStatusCode(HttpStatus.NOT_FOUND_404))
        .execute(Response::andReturn);
  }

  @Test
  public void testNegativeGetRule() {
    apiClient.rawClient()
        .getRule()
        .idPath(777)
        .respSpec(response -> response.expectStatusCode(HttpStatus.NOT_FOUND_404))
        .execute(Response::andReturn);
  }

  @Test
  public void testStartAlreadyStartedRule() {
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
}
