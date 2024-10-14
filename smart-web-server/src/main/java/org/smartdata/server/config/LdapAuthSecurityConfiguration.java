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

import org.smartdata.conf.SmartConf;
import org.smartdata.server.config.PasswordEncoderFactory.EncoderType;
import org.smartdata.server.config.ldap.search.LdapUserSearchFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.authentication.PasswordComparisonAuthenticator;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

import static org.smartdata.server.config.ConfigKeys.LDAP_AUTH_ENABLED;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_AUTH_TYPE;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_BIND_PASSWORD;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_BIND_USER_DN;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_PASSWORD_ENCODER;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_PASSWORD_ENCODER_DEFAULT;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_SEARCH_BASE;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_SEARCH_BASE_DEFAULT;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_URL;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_PASSWORD_ATTR;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_PASSWORD_ATTR_DEFAULT;
import static org.smartdata.server.config.ConfigKeys.WEB_SECURITY_ENABLED;

@Configuration
@ConditionalOnProperty(
    name = {WEB_SECURITY_ENABLED, LDAP_AUTH_ENABLED},
    havingValue = "true")
public class LdapAuthSecurityConfiguration {
  @Bean
  public SsmAuthHttpConfigurer ldapBasicAuthHttpConfigurer() {
    return new SecurityConfiguration.BasicAuthHttpConfigurer();
  }

  @Bean
  public LdapContextSource ldapContextSource(SmartConf conf) {
    Collection<String> ldapUrls = conf.getStringCollection(SMART_REST_SERVER_LDAP_URL);
    Assert.notEmpty(ldapUrls, "At least one LDAP server URL must be provided.");

    String ldapRoot = conf.get(
        SMART_REST_SERVER_LDAP_SEARCH_BASE,
        SMART_REST_SERVER_LDAP_SEARCH_BASE_DEFAULT);

    DefaultSpringSecurityContextSource contextSource =
        new DefaultSpringSecurityContextSource(new ArrayList<>(ldapUrls), ldapRoot);

    Optional.ofNullable(conf.get(SMART_REST_SERVER_LDAP_BIND_USER_DN))
        .ifPresent(contextSource::setUserDn);
    Optional.ofNullable(conf.get(SMART_REST_SERVER_LDAP_BIND_PASSWORD))
        .ifPresent(contextSource::setPassword);

    return contextSource;
  }

  @Bean
  public LdapUserSearch ldapUserSearch(
      SmartConf conf, LdapContextSource contextSource) {
    return LdapUserSearchFactory.fromConfig(contextSource, conf);
  }

  @Bean
  @ConditionalOnProperty(
      name = SMART_REST_SERVER_LDAP_AUTH_TYPE,
      havingValue = "BIND",
      matchIfMissing = true
  )
  public LdapAuthenticator bindLdapAuthenticator(
      LdapContextSource contextSource,
      LdapUserSearch ldapUserSearch) {
    BindAuthenticator authenticator = new BindAuthenticator(contextSource);
    authenticator.setUserSearch(ldapUserSearch);
    return authenticator;
  }

  @Bean
  @ConditionalOnProperty(
      name = SMART_REST_SERVER_LDAP_AUTH_TYPE,
      havingValue = "PASSWORD_COMPARE")
  public LdapAuthenticator passswordCompareLdapAuthenticator(
      SmartConf conf,
      LdapContextSource contextSource,
      LdapUserSearch ldapUserSearch) {
    String passwordAttribute = conf.get(
        SMART_REST_SERVER_LDAP_USER_PASSWORD_ATTR,
        SMART_REST_SERVER_LDAP_USER_PASSWORD_ATTR_DEFAULT);

    PasswordComparisonAuthenticator authenticator = new PasswordComparisonAuthenticator(contextSource);

    authenticator.setPasswordAttributeName(passwordAttribute);
    authenticator.setPasswordEncoder(ldapPasswordEncoder(conf));
    authenticator.setUserSearch(ldapUserSearch);
    return authenticator;
  }

  @Bean
  public AuthenticationProvider ldapAuthenticationProvider(LdapAuthenticator authenticator) {
    return new LdapAuthenticationProvider(authenticator);
  }

  private PasswordEncoder ldapPasswordEncoder(SmartConf smartConf) {
    String defaultEncoder = smartConf.get(
        SMART_REST_SERVER_LDAP_PASSWORD_ENCODER,
        SMART_REST_SERVER_LDAP_PASSWORD_ENCODER_DEFAULT);

    return PasswordEncoderFactory.build(EncoderType.fromId(defaultEncoder));
  }
}
