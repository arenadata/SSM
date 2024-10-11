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
import org.smartdata.conf.SmartConf;
import org.smartdata.server.config.ldap.search.LdapSearchTemplateFactory;
import org.smartdata.server.config.ldap.search.query.LdapExpressionTemplate;
import org.springframework.util.Assert;

import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_GROUP_MEMBER_ATTR;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_GROUP_MEMBER_DEFAULT;
import static org.smartdata.server.config.ldap.search.query.LdapQueryDsl.and;
import static org.smartdata.server.config.ldap.search.query.LdapQueryDsl.eq;

@Slf4j
public class GroupSearchByMemberAttrFactory implements LdapSearchTemplateFactory {
  private static final String USER_DN_TEMPLATE = "{0}";

  private final LdapExpressionTemplate expressionTemplate;

  public GroupSearchByMemberAttrFactory(SmartConf conf) {
    this(new GroupSearchByNameAttrFactory(conf), conf);
  }

  public GroupSearchByMemberAttrFactory(
      LdapSearchTemplateFactory baseGroupSearchTemplateFactory,
      SmartConf conf) {
    Assert.notNull(conf, "conf shouldn't be null");

    String groupMembershipAttribute = conf.get(
        SMART_REST_SERVER_LDAP_GROUP_MEMBER_ATTR,
        SMART_REST_SERVER_LDAP_GROUP_MEMBER_DEFAULT);

    expressionTemplate = and(
        baseGroupSearchTemplateFactory.buildSearchTemplate(),
        eq(groupMembershipAttribute, USER_DN_TEMPLATE)
    );
  }

  @Override
  public LdapExpressionTemplate buildSearchTemplate() {
    return expressionTemplate;
  }
}
