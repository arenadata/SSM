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
import org.smartdata.client.generated.api.RulesApi;
import org.smartdata.client.generated.invoker.ApiClient;
import org.smartdata.client.generated.model.RuleDto;
import org.smartdata.client.generated.model.RulesDto;
import org.smartdata.client.generated.model.RulesInfoDto;
import org.smartdata.client.generated.model.SubmitRuleRequestDto;

import java.time.Duration;

import static org.smartdata.integration.IntegrationTestBase.retryUntil;

public class RulesApiWrapper {

  private final RulesApi apiClient;

  public RulesApiWrapper() {
    this.apiClient = ApiClient.api(ApiClient.Config.apiConfig()).rules();
  }

  public RuleDto getRule(long ruleId) {
    return apiClient.getRule()
        .idPath(ruleId)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .executeAs(Response::andReturn);
  }

  public RulesDto getRules() {
    return apiClient.getRules()
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .executeAs(Response::andReturn);
  }

  public RulesInfoDto getRulesInfo() {
    return apiClient.getRulesInfo()
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .executeAs(Response::andReturn);
  }

  public RuleDto submitRule(String actionText) {
    return apiClient.addRule()
        .body(new SubmitRuleRequestDto().rule(actionText))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .executeAs(Response::andReturn);
  }

  public void startRule(long ruleId) {
    apiClient.startRule()
        .idPath(ruleId)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::andReturn);
  }

  public void stopRule(long ruleId) {
    apiClient.stopRule()
        .idPath(ruleId)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::andReturn);
  }

  public void deleteRule(long ruleId) {
    apiClient.deleteRule()
        .idPath(ruleId)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::andReturn);
  }

  public RuleDto waitTillRuleTriggered(String ruleText, Duration interval, Duration timeout) {
    RuleDto ruleInfo = submitRule(ruleText);
    startRule(ruleInfo.getId());
    return waitTillRuleTriggered(ruleInfo.getId(), interval, timeout);
  }

  public RuleDto waitTillRuleTriggered(long ruleId, Duration interval, Duration timeout) {
    return retryUntil(
        () -> getRule(ruleId),
        rule -> rule.getActivationCount() > 0,
        interval,
        timeout
    );
  }

  public RulesApi rawClient() {
    return apiClient;
  }
}
