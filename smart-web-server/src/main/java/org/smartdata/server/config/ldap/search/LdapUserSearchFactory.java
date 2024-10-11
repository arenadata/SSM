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

import lombok.extern.slf4j.Slf4j;
import org.smartdata.conf.SmartConf;
import org.smartdata.server.config.ldap.search.group.GroupSearchByMemberAttrFactory;
import org.smartdata.server.config.ldap.search.group.GroupSearchRunner;
import org.smartdata.server.config.ldap.search.group.SsmLdapGroupSearch;
import org.smartdata.server.config.ldap.search.user.UserGroupSearchRunner;
import org.smartdata.server.config.ldap.search.user.UserSearchByCustomQueryFactory;
import org.smartdata.server.config.ldap.search.user.UserSearchByMembershipAttrFactory;
import org.smartdata.server.config.ldap.search.user.UserSearchByNameAttributeFactory;
import org.smartdata.server.config.ldap.search.user.UserSearchRunner;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.ldap.search.LdapUserSearch;

import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_CUSTOM_SEARCH;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_GROUP_MEMBER_ATTR;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_GROUPS;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_MEMBER_ATTR;

@Slf4j
public class LdapUserSearchFactory {
  public static LdapUserSearch fromConfig(BaseLdapPathContextSource contextSource, SmartConf conf) {
    if (conf.get(SMART_REST_SERVER_LDAP_CUSTOM_SEARCH) != null) {
      log.info("Search by custom query LDAP authentication strategy enabled");
      return buildSearchByCustomQuery(contextSource, conf);
    }

    if (conf.get(SMART_REST_SERVER_LDAP_USER_GROUPS) != null) {
      if (conf.get(SMART_REST_SERVER_LDAP_USER_MEMBER_ATTR) != null) {
        log.info("Search by user membership attribute LDAP authentication strategy enabled");
        return buildSearchByUserMembershipAttr(contextSource, conf);
      }

      if (conf.get(SMART_REST_SERVER_LDAP_GROUP_MEMBER_ATTR) != null) {
        log.info("Search by group membership attribute LDAP authentication strategy enabled");
        return buildSearchByGroupMemberAttr(contextSource, conf);
      }
    }

    log.info("Search by user name attribute LDAP authentication strategy enabled");
    return buildSearchByUserNameAttr(contextSource, conf);
  }

  private static LdapUserSearch buildSearchByCustomQuery(
      BaseLdapPathContextSource contextSource, SmartConf conf) {
    LdapSearchTemplateFactory templateFactory = new UserSearchByCustomQueryFactory(conf);
    return new UserSearchRunner(contextSource, templateFactory, conf);
  }

  private static LdapUserSearch buildSearchByUserMembershipAttr(
      BaseLdapPathContextSource contextSource, SmartConf conf) {
    SsmLdapGroupSearch groupSearchRunner = new GroupSearchRunner(contextSource, conf);
    LdapSearchTemplateFactory userTemplateFactory =
        new UserSearchByMembershipAttrFactory(groupSearchRunner, conf);
    return new UserSearchRunner(contextSource, userTemplateFactory, conf);
  }

  private static LdapUserSearch buildSearchByGroupMemberAttr(
      BaseLdapPathContextSource contextSource, SmartConf conf) {
    LdapSearchTemplateFactory groupTemplateFactory = new GroupSearchByMemberAttrFactory(conf);
    SsmLdapGroupSearch groupSearchRunner = new GroupSearchRunner(contextSource, conf);
    return new UserGroupSearchRunner(contextSource,
        groupTemplateFactory, groupSearchRunner, conf);
  }

  private static LdapUserSearch buildSearchByUserNameAttr(
      BaseLdapPathContextSource contextSource, SmartConf conf) {
    LdapSearchTemplateFactory templateFactory = new UserSearchByNameAttributeFactory(conf);
    return new UserSearchRunner(contextSource, templateFactory, conf);
  }
}
