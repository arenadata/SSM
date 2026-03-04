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
package org.smartdata.test.step;


import io.arenadata.test.step.BaseApiStep;
import io.qameta.allure.Step;
import io.restassured.response.Response;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.jetty.http.HttpStatus;
import org.smartdata.client.generated.invoker.ApiClient;
import org.smartdata.client.generated.model.ActionInfoDto;
import org.smartdata.client.generated.model.RuleDto;
import org.smartdata.client.generated.model.RulesDto;
import org.smartdata.client.generated.model.SubmitActionRequestDto;
import org.smartdata.client.generated.model.SubmitRuleRequestDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class ApiStep extends BaseApiStep {

  @Autowired
  private ApiClient apiClient;

  @Step("Create rule via API")
  public ApiStep createRule(String ruleText) {
    apiClient.rules().addRule()
        .body(new SubmitRuleRequestDto().rule(ruleText))
        .respSpec(response -> response.expectStatusCode(200))
        .executeAs(Response::andReturn);
    return this;
  }

  @Step("Create rule and start rule via API")
  public ApiStep createAndStartRule(String ruleText) {
    RuleDto ruleDto = apiClient.rules().addRule()
        .body(new SubmitRuleRequestDto().rule(ruleText))
        .respSpec(response -> response.expectStatusCode(200))
        .executeAs(Response::andReturn);
    apiClient.rules().startRule()
        .idPath(ruleDto.getId())
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::andReturn);
    return this;
  }

  @Step("Delete all rules via API")
  public ApiStep deleteAllRules() {
    RulesDto rules = apiClient.rules().getRules()
        .respSpec(response -> response.expectStatusCode(200))
        .executeAs(Response::andReturn);
    if (rules.getItems() != null) {
      rules.getItems().forEach(rule -> apiClient.rules().deleteRule()
          .idPath(rule.getId())
          .respSpec(response -> response.expectStatusCode(200))
          .execute(Response::andReturn));
    }
    return this;
  }

  @Step("Create action via API")
  public ActionInfoDto createAction(String actionText) {
    return apiClient.actions().submitAction()
        .body(new SubmitActionRequestDto().action(actionText))
        .respSpec(response -> response.expectStatusCode(200))
        .executeAs(Response::andReturn);
  }

  @Step("Get raw API client")
  public ApiClient getRawClient() {
    return apiClient;
  }
}
