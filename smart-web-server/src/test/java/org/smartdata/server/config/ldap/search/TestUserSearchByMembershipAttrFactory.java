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

import lombok.RequiredArgsConstructor;
import org.junit.Test;
import org.smartdata.conf.SmartConf;
import org.smartdata.server.config.ldap.search.group.SsmLdapGroupSearch;
import org.smartdata.server.config.ldap.search.query.LdapExpressionTemplate;
import org.smartdata.server.config.ldap.search.user.UserSearchByMembershipAttrFactory;
import org.springframework.ldap.support.LdapUtils;

import javax.naming.Name;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_GROUPS;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_MEMBER_ATTR;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_NAME_ATTR;

public class TestUserSearchByMembershipAttrFactory extends TestLdapSearchTemplateFactory {

  @Override
  protected LdapSearchTemplateFactory create(SmartConf conf) {
    List<String> groups = new ArrayList<>(conf.getStringCollection(
        SMART_REST_SERVER_LDAP_USER_GROUPS));
    return new UserSearchByMembershipAttrFactory(new MockLdapGroupSearch(groups), conf);
  }

  @Test
  public void checkGeneratedQueryWithDefaultConf() {
    SmartConf conf = new SmartConf();
    conf.set(SMART_REST_SERVER_LDAP_USER_GROUPS, "group1,group2");

    String expectedTemplate =
        "(&(objectClass=person)(uid={0})(|(memberOf=cn=group1)(memberOf=cn=group2)))";

    checkGeneratedSearchTemplate(conf, expectedTemplate);
  }

  @Test
  public void checkGeneratedQueryWithCustomConf() {
    SmartConf conf = new SmartConf();
    conf.set(SMART_REST_SERVER_LDAP_USER_GROUPS, "group1");
    conf.set(SMART_REST_SERVER_LDAP_USER_NAME_ATTR, "guid");
    conf.set(SMART_REST_SERVER_LDAP_USER_MEMBER_ATTR, "mmbOf");

    String expectedTemplate =
        "(&(objectClass=person)(guid={0})(mmbOf=cn=group1))";

    checkGeneratedSearchTemplate(conf, expectedTemplate);
  }

  @RequiredArgsConstructor
  private static class MockLdapGroupSearch implements SsmLdapGroupSearch {

    private final List<String> groups;

    @Override
    public List<Name> getGroupDnsFromConfig() {
      return groups.stream()
          .map(name -> LdapUtils.newLdapName("cn=" + name))
          .collect(Collectors.toList());
    }

    @Override
    public List<Name> getGroupDns(LdapExpressionTemplate filter, Object... args) {
      return Collections.emptyList();
    }
  }
}
