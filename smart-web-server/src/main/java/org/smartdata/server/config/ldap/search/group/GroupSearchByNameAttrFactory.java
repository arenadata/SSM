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

import java.util.ArrayList;
import java.util.List;

import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_GROUP_NAME_ATTR;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_GROUP_NAME_DEFAULT;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_GROUP_OBJECT;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_GROUP_OBJECT_DEFAULT;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_GROUPS;
import static org.smartdata.server.config.ldap.search.LdapUtils.isClassObject;
import static org.smartdata.server.config.ldap.search.query.LdapQueryDsl.and;
import static org.smartdata.server.config.ldap.search.query.LdapQueryDsl.eq;
import static org.smartdata.server.config.ldap.search.query.LdapQueryDsl.or;

@Slf4j
public class GroupSearchByNameAttrFactory implements LdapSearchTemplateFactory {
  private final LdapExpressionTemplate expressionTemplate;

  public GroupSearchByNameAttrFactory(SmartConf conf) {
    Assert.notNull(conf, "conf shouldn't be null");

    List<String> groups = new ArrayList<>(conf.getStringCollection(
        SMART_REST_SERVER_LDAP_USER_GROUPS));
    Assert.notEmpty(groups, "filter groups shouldn't be empty");

    String groupObjectClass = conf.get(
        SMART_REST_SERVER_LDAP_GROUP_OBJECT,
        SMART_REST_SERVER_LDAP_GROUP_OBJECT_DEFAULT);
    String groupNameAttribute = conf.get(
        SMART_REST_SERVER_LDAP_GROUP_NAME_ATTR,
        SMART_REST_SERVER_LDAP_GROUP_NAME_DEFAULT);

    expressionTemplate = and(
        isClassObject(groupObjectClass),
        groupHasNameFromConfig(groups, groupNameAttribute)
    );
  }

  @Override
  public LdapExpressionTemplate buildSearchTemplate() {
    return expressionTemplate;
  }

  private LdapExpressionTemplate groupHasNameFromConfig(List<String> groups, String groupNameAttribute) {
    return or(
        groups.stream()
            .map(group -> eq(groupNameAttribute, group))
            .toArray(LdapExpressionTemplate[]::new)
    );
  }
}
