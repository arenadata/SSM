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

import org.junit.Test;
import org.smartdata.conf.SmartConf;
import org.smartdata.server.config.ldap.search.user.UserSearchByNameAttributeFactory;

import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_SEARCH_ADDITIONAL_FILTER;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_NAME_ATTR;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_OBJECT;

public class TestAdditionalFilterTemplateFactoryWrapper extends TestLdapSearchTemplateFactory {

  @Override
  protected LdapSearchTemplateFactory create(SmartConf conf) {
    LdapSearchTemplateFactory baseFactory =
        new UserSearchByNameAttributeFactory(conf);

    return new AdditionalFilterTemplateFactoryWrapper(baseFactory, conf);
  }

  @Test
  public void checkGeneratedQueryWithDefaultConf() {
    String expectedTemplate = "(&(objectClass=person)(uid={0}))";

    checkGeneratedSearchTemplate(new SmartConf(), expectedTemplate);
  }

  @Test
  public void checkGeneratedQueryWithCustomConf() {
    SmartConf conf = new SmartConf();
    conf.set(SMART_REST_SERVER_LDAP_USER_NAME_ATTR, "guid");
    conf.set(SMART_REST_SERVER_LDAP_USER_OBJECT, "person,usr");
    conf.set(SMART_REST_SERVER_LDAP_SEARCH_ADDITIONAL_FILTER, "(|(attr1=test)(attr2=test2))");

    String expectedTemplate =
        "(&(|(objectClass=person)(objectClass=usr))(guid={0})(|(attr1=test)(attr2=test2)))";

    checkGeneratedSearchTemplate(conf, expectedTemplate);
  }
}
