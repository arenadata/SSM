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
import org.smartdata.client.generated.model.RuleDto;
import org.smartdata.client.generated.model.RuleStateDto;
import org.smartdata.client.generated.model.RulesDto;
import org.smartdata.client.generated.model.RulesInfoDto;
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
  public void testSubmitGetRule() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";

    RuleDto rule = apiClient.submitRule(ruleText);
    RuleDto fetchedRule = apiClient.getRule(rule.getId());

    assertEquals(rule.getId(), fetchedRule.getId());
    assertEquals(RuleStateDto.DISABLED, fetchedRule.getState());
    assertEquals(ruleText, fetchedRule.getTextRepresentation());
    assertEquals(0, fetchedRule.getActivationCount().longValue());
    assertEquals(0, fetchedRule.getCmdletsGenerated().longValue());
    assertNull(fetchedRule.getLastActivationTime());
  }

  @Test
  public void testSubmitGetRules() {
    String ruleText = "file: path matches \"/tmp/test/*\" | read";

    RuleDto rule = apiClient.submitRule(ruleText);
    RulesDto fetchedRules = apiClient.getRules();

    assertEquals(1, fetchedRules.getTotal().longValue());
    assertEquals(1, fetchedRules.getItems().size());

    RuleDto fetchedRule = fetchedRules.getItems().get(0);
    assertEquals(rule.getId(), fetchedRule.getId());
    assertEquals(RuleStateDto.DISABLED, rule.getState());
    assertEquals(ruleText, rule.getTextRepresentation());
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
  public void testReturnNotFoundOnUnknownId() {
    apiClient.rawClient()
        .getRule()
        .idPath(777)
        .respSpec(response -> response.expectStatusCode(HttpStatus.NOT_FOUND_404))
        .execute(Response::andReturn);
  }
}
