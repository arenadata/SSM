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

import io.restassured.builder.RequestSpecBuilder;
import io.restassured.response.Response;
import org.eclipse.jetty.http.HttpStatus;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.smartdata.client.generated.invoker.ApiClient;
import org.smartdata.client.generated.model.ActionDto;
import org.smartdata.client.generated.model.ActionInfoDto;
import org.smartdata.client.generated.model.ActionSourceDto;
import org.smartdata.client.generated.model.ActionsDto;
import org.smartdata.conf.SmartConf;
import org.smartdata.integration.api.ActionsApiWrapper;

import java.util.Arrays;

import static io.restassured.config.ObjectMapperConfig.objectMapperConfig;
import static io.restassured.config.RestAssuredConfig.config;
import static org.junit.Assert.assertEquals;
import static org.smartdata.client.generated.invoker.JacksonObjectMapper.jackson;
import static org.smartdata.http.config.ConfigKeys.SSL_ENABLED;
import static org.smartdata.http.config.ConfigKeys.SSL_KEYSTORE_PASSWORD;
import static org.smartdata.http.config.ConfigKeys.SSL_KEYSTORE_PATH;
import static org.smartdata.http.config.ConfigKeys.SSL_KEY_ALIAS;
import static org.smartdata.http.config.ConfigKeys.SSL_KEY_PASSWORD;

@RunWith(Parameterized.class)
public class TestSsl extends IntegrationTestBase {

  private static final String TRUST_STORE_PATH = "ssl/truststore.jks";
  private static final String TRUST_STORE_PASSWORD = "password";
  private static final String SECURED_SERVER_URL = "https://localhost:8081";

  private ActionsApiWrapper securedActionsApiClient;

  @Before
  public void createApi() {
    ApiClient.Config config = ApiClient.Config.apiConfig()
        .reqSpecSupplier(TestSsl::defaultRequestBuilder);
    securedActionsApiClient = new ActionsApiWrapper(config);
  }

  @Parameter
  public SmartConf sslConfig;

  @Parameters
  public static Iterable<SmartConf> parameters() {
    return Arrays.asList(
        withJksKeyPassword(),
        withJksNoKeyPassword(),
        withJksInClasspath(),
        withPkcs12(),
        withPkcs12InClasspath()
    );
  }

  @Override
  protected SmartConf withSsmServerOptions(SmartConf conf) {
    conf.addResource(sslConfig);
    return conf;
  }

  @Test
  public void testHttpsRequests() {
    ActionsDto actions = securedActionsApiClient.getActions();
    assertEquals(0L, actions.getTotal().longValue());

    String actionText = "read -file /tmp/text.txt";
    ActionInfoDto actionInfo = securedActionsApiClient.submitAction(actionText);

    assertEquals(ActionSourceDto.USER, actionInfo.getSource());

    ActionDto fetchedAction = securedActionsApiClient.getAction(actionInfo.getId());

    assertEquals(actionInfo.getId(), fetchedAction.getId());
  }

  @Test
  public void testHttpRequestFails() {
    ActionsApiWrapper insecureApiClient = new ActionsApiWrapper();
    insecureApiClient.rawClient()
        .getActions()
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
  }


  private static SmartConf withPkcs12() {
    SmartConf conf = new SmartConf();
    conf.setBoolean(SSL_ENABLED, true);
    conf.set(SSL_KEYSTORE_PATH, resourceAbsolutePath("ssl/keystore.p12"));
    conf.set(SSL_KEYSTORE_PASSWORD, "p12_password");
    conf.set(SSL_KEY_ALIAS, "self_signed");
    return conf;
  }

  private static SmartConf withPkcs12InClasspath() {
    SmartConf conf = new SmartConf();
    conf.setBoolean(SSL_ENABLED, true);
    conf.set(SSL_KEYSTORE_PATH, "classpath:ssl/keystore.p12");
    conf.set(SSL_KEYSTORE_PASSWORD, "p12_password");
    conf.set(SSL_KEY_ALIAS, "self_signed");
    return conf;
  }

  private static SmartConf withJksKeyPassword() {
    SmartConf conf = new SmartConf();
    conf.setBoolean(SSL_ENABLED, true);
    conf.set(SSL_KEYSTORE_PATH, "classpath:ssl/keystore.jks");
    conf.set(SSL_KEYSTORE_PASSWORD, "password");
    conf.set(SSL_KEY_ALIAS, "selfsigned");
    conf.set(SSL_KEY_PASSWORD, "key_password");
    return conf;
  }

  private static SmartConf withJksInClasspath() {
    SmartConf conf = new SmartConf();
    conf.setBoolean(SSL_ENABLED, true);
    conf.set(SSL_KEYSTORE_PATH, resourceAbsolutePath("ssl/keystore.jks"));
    conf.set(SSL_KEYSTORE_PASSWORD, "password");
    conf.set(SSL_KEY_ALIAS, "selfsigned");
    conf.set(SSL_KEY_PASSWORD, "key_password");
    return conf;
  }

  private static SmartConf withJksNoKeyPassword() {
    SmartConf conf = new SmartConf();
    conf.setBoolean(SSL_ENABLED, true);
    conf.set(SSL_KEYSTORE_PATH, resourceAbsolutePath("ssl/no-password-keystore.jks"));
    conf.set(SSL_KEYSTORE_PASSWORD, "password");
    conf.set(SSL_KEY_ALIAS, "selfsigned");
    return conf;
  }

  private static RequestSpecBuilder defaultRequestBuilder() {
    return new RequestSpecBuilder()
        .setConfig(config().objectMapperConfig(objectMapperConfig().defaultObjectMapper(jackson())))
        .setBaseUri(SECURED_SERVER_URL)
        .setTrustStore(resourceAbsolutePath(TRUST_STORE_PATH), TRUST_STORE_PASSWORD);
  }
}
