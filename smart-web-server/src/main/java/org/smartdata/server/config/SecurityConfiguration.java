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

import org.smartdata.security.SmartPrincipalManager;
import org.smartdata.server.security.SmartPrincipalInitializerFilter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.List;

@Configuration
public class SecurityConfiguration {
  private static final String SESSION_COOKIE_NAME = "SSM_SESSIONID";

  @Bean
  @ConditionalOnProperty(name = ConfigKeys.WEB_SECURITY_ENABLED, havingValue = "true")
  public AuthenticationManager authenticationManager(
      List<AuthenticationProvider> authenticationProviders) {
    if (authenticationProviders.isEmpty()) {
      throw new IllegalArgumentException(
          "REST server security is enabled, but no authentication method is provided");
    }
    return new ProviderManager(authenticationProviders);
  }

  @Bean
  @ConditionalOnProperty(name = ConfigKeys.WEB_SECURITY_ENABLED, havingValue = "true")
  public SecurityFilterChain securityFilterChain(
      HttpSecurity http,
      SmartPrincipalManager principalManager,
      List<SsmAuthHttpConfigurer> authHttpConfigurers,
      AuthorizationManager<RequestAuthorizationContext> authorizationManager) throws Exception {
    baseHttpSecurity(http)
        .authorizeHttpRequests(
            authorize -> authorize.antMatchers("/api/**").access(authorizationManager))
        .anonymous(AbstractHttpConfigurer::disable)
        .addFilterAfter(
            new SmartPrincipalInitializerFilter(principalManager),
            BasicAuthenticationFilter.class);

    for (SsmAuthHttpConfigurer configurer : authHttpConfigurers) {
      http.apply(configurer);
    }

    return http.build();
  }

  @Bean
  @ConditionalOnProperty(
      name = ConfigKeys.WEB_SECURITY_ENABLED,
      havingValue = "false",
      matchIfMissing = true)
  public SecurityFilterChain disabledSecurityFilterChain(HttpSecurity http) throws Exception {
    baseHttpSecurity(http)
        .authorizeRequests()
        .anyRequest()
        .permitAll();
    return http.build();
  }

  private HttpSecurity baseHttpSecurity(HttpSecurity http) throws Exception {
    return http.cors().disable()
        .csrf().disable()
        .logout(logout -> logout.deleteCookies(SESSION_COOKIE_NAME)
            .logoutUrl("/api/v2/logout")
            .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler()));
  }

  public static class BasicAuthHttpConfigurer extends SsmAuthHttpConfigurer {
    @Override
    public void init(HttpSecurity http) throws Exception {
      http.httpBasic();
    }
  }
}
