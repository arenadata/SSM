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
import org.smartdata.conf.SmartConf;
import org.smartdata.server.config.ldap.search.LdapSearchTemplateFactory;
import org.smartdata.server.config.ldap.search.group.SsmLdapGroupSearch;
import org.smartdata.server.config.ldap.search.query.LdapExpressionTemplate;
import org.springframework.util.Assert;

import java.util.Set;
import java.util.stream.Collectors;

import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_MEMBER_ATTR;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_MEMBER_ATTR_DEFAULT;
import static org.smartdata.server.config.ldap.search.query.LdapQueryDsl.and;
import static org.smartdata.server.config.ldap.search.query.LdapQueryDsl.eq;
import static org.smartdata.server.config.ldap.search.query.LdapQueryDsl.or;

@Slf4j
public class UserSearchByMembershipAttrFactory implements LdapSearchTemplateFactory {
  private final String userMembershipAttribute;
  private final LdapSearchTemplateFactory baseUserSearch;
  private final SsmLdapGroupSearch groupSearch;

  public UserSearchByMembershipAttrFactory(
      SsmLdapGroupSearch groupSearch,
      SmartConf conf) {
    this(new UserSearchByNameAttributeFactory(conf), groupSearch, conf);
  }

  public UserSearchByMembershipAttrFactory(
      LdapSearchTemplateFactory baseUserSearch,
      SsmLdapGroupSearch groupSearchRunner,
      SmartConf conf) {
    Assert.notNull(conf, "conf shouldn't be null");
    Assert.notNull(groupSearchRunner, "groupSearchRunner shouldn't be null");
    Assert.notNull(baseUserSearch, "baseUserSearch shouldn't be null");

    this.baseUserSearch = baseUserSearch;
    this.userMembershipAttribute = conf.get(
        SMART_REST_SERVER_LDAP_USER_MEMBER_ATTR,
        SMART_REST_SERVER_LDAP_USER_MEMBER_ATTR_DEFAULT
    );
    this.groupSearch = groupSearchRunner;
  }

  @Override
  public LdapExpressionTemplate buildSearchTemplate() {
    Set<String> groupDns = groupSearch.getGroupDnsFromConfig()
        .stream()
        .map(Object::toString)
        .collect(Collectors.toSet());

    return and(
        baseUserSearch.buildSearchTemplate(),
        isUserMemberOfGroups(groupDns)
    );
  }

  private LdapExpressionTemplate isUserMemberOfGroups(Set<String> groups) {
    return or(
        groups.stream()
            .map(this::isMemberOfGroup)
            .toArray(LdapExpressionTemplate[]::new)
    );
  }

  private LdapExpressionTemplate isMemberOfGroup(String group) {
    return eq(userMembershipAttribute, group);
  }
}
