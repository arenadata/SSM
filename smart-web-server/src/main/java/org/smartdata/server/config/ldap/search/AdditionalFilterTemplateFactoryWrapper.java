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
package org.smartdata.server.config.ldap.search;

import org.smartdata.conf.SmartConf;
import org.smartdata.server.config.ldap.search.query.LdapExpressionTemplate;
import org.springframework.util.Assert;

import java.util.Optional;

import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_SEARCH_ADDITIONAL_FILTER;
import static org.smartdata.server.config.ldap.search.query.LdapQueryDsl.and;

public class AdditionalFilterTemplateFactoryWrapper
    implements LdapSearchTemplateFactory {

  private final LdapExpressionTemplate additionalFilterTemplate;
  private final LdapSearchTemplateFactory baseTemplateFactory;

  public AdditionalFilterTemplateFactoryWrapper(
      LdapSearchTemplateFactory baseTemplateFactory, SmartConf conf) {
    Assert.notNull(conf, "conf shouldn't be null");
    Assert.notNull(baseTemplateFactory, "baseTemplateFactory shouldn't be null");

    this.baseTemplateFactory = baseTemplateFactory;
    this.additionalFilterTemplate =
        Optional.ofNullable(conf.get(SMART_REST_SERVER_LDAP_SEARCH_ADDITIONAL_FILTER))
            .map(LdapExpressionTemplate::custom)
            .orElseGet(LdapExpressionTemplate::empty);
  }

  @Override
  public LdapExpressionTemplate buildSearchTemplate() {
    LdapExpressionTemplate template = baseTemplateFactory.buildSearchTemplate();
    return additionalFilterTemplate.isEmpty()
        ? template
        : and(template, additionalFilterTemplate);
  }
}
