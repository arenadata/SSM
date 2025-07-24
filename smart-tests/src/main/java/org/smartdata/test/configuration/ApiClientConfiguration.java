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
package org.smartdata.test.configuration;

import io.arenadata.test.model.UserRole;
import io.arenadata.test.service.UserProvider;
import io.restassured.builder.RequestSpecBuilder;
import lombok.Setter;
import org.smartdata.client.generated.invoker.ApiClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Base64;

import static io.restassured.config.ObjectMapperConfig.objectMapperConfig;
import static io.restassured.config.RestAssuredConfig.config;
import static java.lang.String.format;
import static org.smartdata.client.generated.invoker.ApiClient.BASE_URI;
import static org.smartdata.client.generated.invoker.JacksonObjectMapper.jackson;

@Configuration
@Setter
public class ApiClientConfiguration {

  @Autowired
  private UserProvider<UserRole> ssmUserProvider;

  @Bean
  public ApiClient apiClient() {
    return ApiClient.api(ApiClient.Config.apiConfig()
        .reqSpecSupplier(this::apiClientRequestSpecBuilder));
  }

  private RequestSpecBuilder apiClientRequestSpecBuilder() {
    String user = ssmUserProvider.getUserModel(UserRole.OWNER).getLogin();
    String password = ssmUserProvider.getUserModel(UserRole.OWNER).getPassword();
    String credentials = Base64.getEncoder().encodeToString((format("%s:%s", user, password)).getBytes());
    return new RequestSpecBuilder()
        .setBaseUri(BASE_URI)
        .setConfig(config().objectMapperConfig(objectMapperConfig().defaultObjectMapper(jackson())))
        .addHeader("Authorization", format("Basic %s", credentials));
  }
}
