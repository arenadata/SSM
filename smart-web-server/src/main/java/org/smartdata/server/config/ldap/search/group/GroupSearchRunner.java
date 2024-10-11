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
package org.smartdata.server.config.ldap.search.group;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.smartdata.conf.SmartConf;
import org.smartdata.server.config.ldap.search.LdapSearchScope;
import org.smartdata.server.config.ldap.search.LdapSearchTemplateFactory;
import org.smartdata.server.config.ldap.search.query.LdapExpressionTemplate;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.util.Assert;

import javax.naming.Name;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.LdapName;

import java.util.List;
import java.util.Optional;

import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_GROUP_SEARCH_BASE;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_GROUP_SEARCH_SCOPE;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_GROUP_SEARCH_SCOPE_DEFAULT;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_SEARCH_BASE;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_SEARCH_BASE_DEFAULT;
import static org.smartdata.server.config.ldap.search.LdapUtils.formatTemplate;
import static org.smartdata.server.config.ldap.search.LdapUtils.getRelativeBaseName;

@Slf4j
public class GroupSearchRunner implements SsmLdapGroupSearch {

  private final BaseLdapPathContextSource contextSource;
  private final LdapName searchBase;
  private final SpringSecurityLdapTemplate ldapTemplate;
  private final String filterTemplate;

  public GroupSearchRunner(
      BaseLdapPathContextSource contextSource,
      SmartConf conf) {
    this(contextSource, new GroupSearchByNameAttrFactory(conf), conf);
  }

  public GroupSearchRunner(
      BaseLdapPathContextSource contextSource,
      LdapSearchTemplateFactory baseGroupSearchTemplateFactory,
      SmartConf conf) {
    Assert.notNull(conf, "conf shouldn't be null");
    Assert.notNull(baseGroupSearchTemplateFactory,
        "baseGroupSearchTemplateFactory shouldn't be null");
    Assert.notNull(contextSource, "contextSource shouldn't be null");

    String rawSearchBase = Optional.ofNullable(
            conf.get(SMART_REST_SERVER_LDAP_GROUP_SEARCH_BASE))
        .filter(StringUtils::isNotBlank)
        .orElseGet(() -> conf.get(
            SMART_REST_SERVER_LDAP_SEARCH_BASE,
            SMART_REST_SERVER_LDAP_SEARCH_BASE_DEFAULT));
    if (StringUtils.isBlank(rawSearchBase)) {
      log.info("Searches will be performed from the root {} since SearchBase not set",
          contextSource.getBaseLdapName());
    }
    this.searchBase = getRelativeBaseName(
        rawSearchBase, contextSource.getBaseLdapName());
    this.contextSource = contextSource;
    SearchControls searchControls = new SearchControls();
    LdapSearchScope searchScope = conf.getEnum(
        SMART_REST_SERVER_LDAP_GROUP_SEARCH_SCOPE,
        SMART_REST_SERVER_LDAP_GROUP_SEARCH_SCOPE_DEFAULT);
    searchControls.setSearchScope(searchScope.getValue());

    this.filterTemplate = baseGroupSearchTemplateFactory.buildSearchTemplate().build();
    this.ldapTemplate = new SpringSecurityLdapTemplate(contextSource);
    ldapTemplate.setSearchControls(searchControls);
  }

  @Override
  public List<Name> getGroupDnsFromConfig() {
    return getGroupDns(filterTemplate);
  }

  @Override
  public List<Name> getGroupDns(LdapExpressionTemplate filter, Object... args) {
    return getGroupDns(formatTemplate(filter, args));
  }

  private List<Name> getGroupDns(String filter) {
    return ldapTemplate.search(searchBase, filter,
        (ContextMapper<Name>) this::getNameFromCtx);
  }

  private Name getNameFromCtx(Object rawCtx) {
    DirContextAdapter ctx = (DirContextAdapter) rawCtx;
    return LdapUtils.prepend(ctx.getDn(), contextSource.getBaseLdapName());
  }
}
