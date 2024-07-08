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
package org.smartdata.server.config;

import org.smartdata.ranger.authorizer.impl.RangerSsmAuthorizerImpl;
import org.smartdata.server.security.NoneAuthorizationManager;
import org.smartdata.server.security.RangerAuthorizationManager;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import static org.smartdata.server.config.ConfigKeys.RANGER_AUTHORIZATION_ENABLED;
import static org.smartdata.server.config.ConfigKeys.WEB_SECURITY_ENABLED;

@Configuration
public class AuthorizationConfiguration {

  @ConditionalOnProperty(
      name = {WEB_SECURITY_ENABLED, RANGER_AUTHORIZATION_ENABLED},
      havingValue = "true")
  @Bean
  public AuthorizationManager<RequestAuthorizationContext> rangerAuthorizationManager() {
    return new RangerAuthorizationManager(new RangerSsmAuthorizerImpl());
  }

  @ConditionalOnProperty(
      name = ConfigKeys.WEB_SECURITY_ENABLED,
      havingValue = "false",
      matchIfMissing = true)
  @Bean
  public AuthorizationManager<RequestAuthorizationContext> noneAuthorizationManager() {
    return new NoneAuthorizationManager();
  }
}
