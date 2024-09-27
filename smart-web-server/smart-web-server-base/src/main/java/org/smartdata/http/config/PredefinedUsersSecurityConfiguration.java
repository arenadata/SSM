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
package org.smartdata.http.config;

import org.smartdata.conf.SmartConf;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.List;

import static org.smartdata.http.config.ConfigKeys.PREDEFINED_BASIC_AUTH_ENABLED;
import static org.smartdata.http.config.ConfigKeys.WEB_SECURITY_ENABLED;
import static org.smartdata.http.util.ConfigUtils.parsePredefinedUsers;

@Configuration
@ConditionalOnProperty(
    name = {WEB_SECURITY_ENABLED, PREDEFINED_BASIC_AUTH_ENABLED},
    havingValue = "true")
public class PredefinedUsersSecurityConfiguration {

  @Bean
  public AuthenticationProvider predefinedUsersAuthenticationProvider(
      SmartConf smartConf) {
    DaoAuthenticationProvider predefinedUsersProvider = new DaoAuthenticationProvider();
    List<UserDetails> predefinedUsers = parsePredefinedUsers(smartConf);
    predefinedUsersProvider.setUserDetailsService(
        new InMemoryUserDetailsManager(predefinedUsers));
    return predefinedUsersProvider;
  }

  @Bean
  public SsmAuthHttpConfigurer basicAuthHttpConfigurer() {
    return new SecurityConfiguration.BasicAuthHttpConfigurer();
  }
}
