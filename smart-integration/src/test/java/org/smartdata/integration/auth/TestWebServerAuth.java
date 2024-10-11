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
package org.smartdata.integration.auth;

import io.restassured.authentication.BasicAuthScheme;
import io.restassured.builder.RequestSpecBuilder;
import io.restassured.response.Response;
import org.eclipse.jetty.http.HttpStatus;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.smartdata.client.generated.invoker.ApiClient;
import org.smartdata.client.generated.model.ActionsDto;
import org.smartdata.conf.SmartConf;
import org.smartdata.integration.IntegrationTestBase;
import org.smartdata.integration.api.ActionsApiWrapper;

import java.util.Optional;

import static io.restassured.config.ObjectMapperConfig.objectMapperConfig;
import static io.restassured.config.RestAssuredConfig.config;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.smartdata.client.generated.invoker.ApiClient.BASE_URI;
import static org.smartdata.client.generated.invoker.JacksonObjectMapper.jackson;
import static org.smartdata.server.config.ConfigKeys.WEB_SECURITY_ENABLED;

@RunWith(Parameterized.class)
public abstract class TestWebServerAuth extends IntegrationTestBase {

  protected static final String TEST_PARAM_NAME_OPTION = "internal.test.param.name";

  private ActionsApiWrapper actionsApiWrapper;

  @Parameter
  public TestParams testParams;

  @Before
  public void createApi() {
    actionsApiWrapper = new ActionsApiWrapper(
        ApiClient.Config.apiConfig().reqSpecSupplier(this::withAuth));
  }

  @Override
  protected SmartConf withSsmServerOptions(SmartConf conf) {
    conf.addResource(testParams.authConf);
    conf.setBoolean(WEB_SECURITY_ENABLED, true);
    return conf;
  }

  @Test
  public void testSendRequestWithAuthentication() {
    if (testParams.expectedResult == TestParams.ExpectedResult.SUCCESS) {
      testSuccessfulAuthentication();
    } else {
      testUnsuccessfulAuthentication();
    }
  }

  private void testUnsuccessfulAuthentication() {
    actionsApiWrapper.rawClient()
        .getActions()
        .respSpec(response -> response.expectStatusCode(HttpStatus.UNAUTHORIZED_401))
        .executeAs(Response::andReturn);
  }

  private void testSuccessfulAuthentication() {
    ActionsDto actionsDto = actionsApiWrapper.getActions();

    assertEquals(0, actionsDto.getTotal().longValue());
    assertNotNull(actionsDto.getItems());
    assertTrue(actionsDto.getItems().isEmpty());

    actionsApiWrapper.submitAction("read -file text.txt");
  }

  private RequestSpecBuilder withAuth() {
    BasicAuthScheme authScheme = new BasicAuthScheme();
    authScheme.setUserName(testParams.username);
    authScheme.setPassword(testParams.password);

    return new RequestSpecBuilder()
        .setBaseUri(BASE_URI)
        .setConfig(config().objectMapperConfig(objectMapperConfig().defaultObjectMapper(jackson())))
        .setAuth(authScheme);
  }

  public static class TestParams {
    private final String username;
    private final String password;
    private final SmartConf authConf;
    private final ExpectedResult expectedResult;

    public enum ExpectedResult {
      FAIL,
      SUCCESS
    }

    public TestParams(String username, String password, SmartConf authConf) {
      this(username, password, authConf, ExpectedResult.SUCCESS);
    }

    public TestParams(String username, String password, SmartConf authConf, ExpectedResult expectedResult) {
      this.username = username;
      this.password = password;
      this.authConf = authConf;
      this.expectedResult = expectedResult;
    }

    @Override
    public String toString() {
      return Optional.ofNullable(authConf.get(TEST_PARAM_NAME_OPTION))
          .map(name -> name + ": ")
          .orElse("") + username + ":" + password;
    }
  }
}
