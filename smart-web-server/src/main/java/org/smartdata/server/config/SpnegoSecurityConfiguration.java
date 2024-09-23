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

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.security.SecurityUtil;
import org.smartdata.conf.SmartConf;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.util.Optional;

import static org.smartdata.conf.SmartConfKeys.SMART_SERVER_KEYTAB_FILE_KEY;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_KERBEROS_PRINCIPAL;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_KEYTAB_FILE_KEY;
import static org.smartdata.server.config.ConfigKeys.SPNEGO_AUTH_ENABLED;
import static org.smartdata.server.config.ConfigKeys.WEB_SECURITY_ENABLED;

@Configuration
@ConditionalOnProperty(
    name = {WEB_SECURITY_ENABLED, SPNEGO_AUTH_ENABLED},
    havingValue = "true")
public class SpnegoSecurityConfiguration {
  @Bean
  public SsmAuthHttpConfigurer spnegoAuthHttpConfigurer(
      AuthenticationManager authManager) {
    return new SsmSpnegoAuthHttpConfigurer(spnegoAuthFilter(authManager));
  }

  @Bean
  public AuthenticationProvider kerberosServiceAuthenticationProvider(
      SunJaasKerberosTicketValidator kerberosTicketValidator) {
    KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
    provider.setTicketValidator(kerberosTicketValidator);
    provider.setUserDetailsService(
        KerberosBasicAuthSecurityConfiguration.kerberosUserDetailsService());
    return provider;
  }

  @Bean
  public SunJaasKerberosTicketValidator kerberosTicketValidator(
      SmartConf smartConf) throws IOException {
    // replace _HOST with actual hostname
    String principal = SecurityUtil.getServerPrincipal(
        smartConf.getNonEmpty(SMART_REST_SERVER_KERBEROS_PRINCIPAL), "");
    String keytabPath = getKeytabPath(smartConf);

    SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
    ticketValidator.setServicePrincipal(principal);
    ticketValidator.setKeyTabLocation(new FileSystemResource(keytabPath));
    return ticketValidator;
  }

  private String getKeytabPath(SmartConf smartConf) {
    return Optional.ofNullable(smartConf.get(SMART_REST_SERVER_KEYTAB_FILE_KEY))
        .filter(StringUtils::isNotBlank)
        .orElseGet(() -> smartConf.getNonEmpty(
            SMART_SERVER_KEYTAB_FILE_KEY,
            "SSM principal keytab for SPNEGO is not provided. "
                + "Please specify it either in the 'smart.rest.server.auth.spnego.keytab' "
                + "or in the 'smart.server.keytab.file' option."));
  }

  private SpnegoAuthenticationProcessingFilter spnegoAuthFilter(
      AuthenticationManager authManager) {
    SpnegoAuthenticationProcessingFilter spnegoAuthFilter =
        new SpnegoAuthenticationProcessingFilter();
    spnegoAuthFilter.setAuthenticationManager(authManager);
    return spnegoAuthFilter;
  }

  @RequiredArgsConstructor
  public static class SsmSpnegoAuthHttpConfigurer extends SsmAuthHttpConfigurer {

    private final SpnegoAuthenticationProcessingFilter spnegoAuthFilter;

    @Override
    public void init(HttpSecurity http) throws Exception {
      http.exceptionHandling()
          .authenticationEntryPoint(new SpnegoEntryPoint())
          .and()
          .addFilterAfter(spnegoAuthFilter, BasicAuthenticationFilter.class);
    }
  }

}
