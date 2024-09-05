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
package org.smartdata.server.config.ldap.search.user;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.smartdata.conf.SmartConf;
import org.smartdata.server.config.ldap.search.LdapSearchScope;
import org.smartdata.server.config.ldap.search.LdapSearchTemplateFactory;
import org.smartdata.server.config.ldap.search.query.LdapExpressionTemplate;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.util.Assert;

import javax.naming.directory.SearchControls;
import javax.naming.ldap.LdapName;

import java.util.Optional;

import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_SEARCH_ADDITIONAL_FILTER;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_SEARCH_BASE;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_SEARCH_BASE;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_SEARCH_SCOPE;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_SEARCH_SCOPE_DEFAULT;
import static org.smartdata.server.config.ldap.search.LdapUtils.getRelativeBaseName;
import static org.smartdata.server.config.ldap.search.query.LdapQueryDsl.and;

@Slf4j
public class UserSearchRunner implements SsmLdapUserSearch {
  protected final BaseLdapPathContextSource contextSource;

  protected final LdapName searchBase;
  protected final String additionalCustomSearch;
  protected final SearchControls searchControls;
  protected final SpringSecurityLdapTemplate ldapTemplate;

  private final LdapSearchTemplateFactory templateFactory;

  public UserSearchRunner(
      BaseLdapPathContextSource contextSource,
      LdapSearchTemplateFactory templateFactory,
      SmartConf conf) {
    Assert.notNull(contextSource, "contextSource must not be null");
    Assert.notNull(templateFactory, "templateFactory must not be null");
    Assert.notNull(conf, "conf must not be null.");

    this.contextSource = contextSource;
    this.templateFactory = templateFactory;

    String rawSearchBase = Optional.ofNullable(conf.get(SMART_REST_SERVER_LDAP_USER_SEARCH_BASE))
        .filter(StringUtils::isNotBlank)
        .orElseGet(() -> conf.get(SMART_REST_SERVER_LDAP_SEARCH_BASE));
    if (StringUtils.isBlank(rawSearchBase)) {
      log.info("Searches will be performed from the root {} since SearchBase not set",
          contextSource.getBaseLdapName());
    }

    this.searchBase = getRelativeBaseName(
        rawSearchBase, contextSource.getBaseLdapName());
    this.additionalCustomSearch = conf.get(
        SMART_REST_SERVER_LDAP_SEARCH_ADDITIONAL_FILTER);

    this.searchControls = new SearchControls();
    LdapSearchScope searchScope = conf.getEnum(
        SMART_REST_SERVER_LDAP_USER_SEARCH_SCOPE,
        SMART_REST_SERVER_LDAP_USER_SEARCH_SCOPE_DEFAULT);
    searchControls.setSearchScope(searchScope.getValue());

    this.ldapTemplate = new SpringSecurityLdapTemplate(contextSource);
    ldapTemplate.setSearchControls(searchControls);
  }

  @Override
  public DirContextOperations searchForUser(String username) throws UsernameNotFoundException {
    try {
      return ldapTemplate.searchForSingleEntry(
          searchBase.toString(), getSearchTemplate().build(), new Object[]{username});
    } catch (IncorrectResultSizeDataAccessException ex) {
      if (ex.getActualSize() == 0) {
        throw new UsernameNotFoundException("User " + username + " not found in directory.");
      }
      // Search should never return multiple results if properly configured
      throw ex;
    }
  }

  @Override
  public LdapExpressionTemplate getSearchTemplate() {
    LdapExpressionTemplate template = templateFactory.buildSearchTemplate();
    return StringUtils.isBlank(additionalCustomSearch)
        ? template
        : and(template, LdapExpressionTemplate.custom(additionalCustomSearch));
  }
}
