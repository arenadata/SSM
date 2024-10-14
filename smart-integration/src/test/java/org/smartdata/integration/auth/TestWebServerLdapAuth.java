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
package org.smartdata.integration.auth;

import com.unboundid.ldap.sdk.LDAPException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runners.Parameterized.Parameters;
import org.smartdata.conf.SmartConf;
import org.smartdata.server.config.PasswordEncoderFactory.EncoderType;
import org.smartdata.server.config.ldap.search.LdapSearchScope;

import static org.smartdata.integration.auth.TestWebServerAuth.TestParams.ExpectedResult.FAIL;
import static org.smartdata.integration.auth.TestWebServerLdapAuth.AuthType.BIND;
import static org.smartdata.integration.auth.TestWebServerLdapAuth.AuthType.PASSWORD_COMPARE;
import static org.smartdata.server.config.ConfigKeys.LDAP_AUTH_ENABLED;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_AUTH_TYPE;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_BIND_PASSWORD;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_BIND_USER_DN;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_CUSTOM_SEARCH;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_GROUP_MEMBER_ATTR;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_GROUP_NAME_ATTR;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_GROUP_OBJECT_DEFAULT;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_PASSWORD_ENCODER;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_SEARCH_ADDITIONAL_FILTER;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_SEARCH_BASE;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_URL;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_GROUPS;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_MEMBER_ATTR;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_SEARCH_BASE;
import static org.smartdata.server.config.ConfigKeys.SMART_REST_SERVER_LDAP_USER_SEARCH_SCOPE;


public class TestWebServerLdapAuth extends TestWebServerAuth {
  private static final String LDAP_BASE_DN = "dc=ssm,dc=test";
  private static final String LDAP_BIND_DN = "uid=admin,ou=system";
  private static final String LDAP_BIND_PASSWORD = "secret";
  private static final String LDAP_LDIF_RESOURCE_PATH = "ldap-server.ldif";
  private static final int LDAP_TEST_SERVER_PORT = 53389;

  private static InMemoryLdapServer inMemoryLdapServer;

  @BeforeClass
  public static void startTestLdapServer() throws LDAPException {
    inMemoryLdapServer = InMemoryLdapServer.builder()
        .baseDn(LDAP_BASE_DN)
        .port(LDAP_TEST_SERVER_PORT)
        .bindDn(LDAP_BIND_DN)
        .bindPassword(LDAP_BIND_PASSWORD)
        .ldifResourcePath(LDAP_LDIF_RESOURCE_PATH)
        .build();

    inMemoryLdapServer.start();
  }

  @AfterClass
  public static void stopTestLdapServer() {
    inMemoryLdapServer.stop();
  }

  @Parameters(name = "{0}")
  public static TestParams[] parameters() {
    return new TestParams[]{
        new TestParams("ben", "bens_password",
            searchByName(BIND)),
        new TestParams("bob", "b0bs_p4ssw0rd",
            searchByName(PASSWORD_COMPARE)),
        new TestParams("unknown", "pass",
            searchByName(PASSWORD_COMPARE), FAIL),
        new TestParams("bob", "b0bs_p4ssw0rd",
            searchByGroupMemberAttr(BIND, "managers")),
        new TestParams("bob", "b0bs_p4ssw0rd",
            searchByGroupMemberAttr(BIND, "unknownGroup"), FAIL),
        new TestParams("ben", "bens_password",
            searchByGroupMemberAttr(PASSWORD_COMPARE, "managers"), FAIL),
        new TestParams("ben", "bens_password",
            searchByUserMemberAttr(PASSWORD_COMPARE, "developers")),
        new TestParams("july", "kitty_cat",
            searchByUserMemberAttr(PASSWORD_COMPARE, "developers")),
        new TestParams("ben", "bens_password",
            searchByUserMemberAttr(PASSWORD_COMPARE, "unknownGroup2"), FAIL),
        new TestParams("bob", "b0bs_p4ssw0rd",
            searchByUserMemberAttr(BIND, "developers"), FAIL),
        new TestParams("bob", "b0bs_p4ssw0rd",
            searchByCustomSearch(BIND), FAIL),
        new TestParams("july", "kitty_cat",
            searchByCustomSearch(PASSWORD_COMPARE)),
        new TestParams("july", "kitty_cat",
            searchWithAdditionalSearch(PASSWORD_COMPARE)),
        new TestParams("july", "kitty_cat",
            searchWithAdditionalSearch(BIND)),
        new TestParams("ben", "bens_password",
            searchWithAdditionalSearch(BIND), FAIL),
        new TestParams("hashed_bob", "b0bs_p4ssw0rd",
            passwordCompareWithPasswordEncoding(EncoderType.NOOP)),
        new TestParams("hashed_july", "kitty_cat",
            passwordCompareWithPasswordEncoding(EncoderType.NOOP), FAIL),
        new TestParams("hashed_july", "kitty_cat",
            passwordCompareWithPasswordEncoding(EncoderType.PBKDF2)),
        new TestParams("july", "kitty_cat",
            searchByCustomSearchSeveralUsers(BIND), FAIL),
        new TestParams("july", "kitty_cat",
            searchByCustomSearchSeveralUsers(PASSWORD_COMPARE), FAIL)
    };
  }

  private static SmartConf searchByName(AuthType authType) {
    SmartConf conf = baseConf();
    conf.set(SMART_REST_SERVER_LDAP_AUTH_TYPE, authType.toString());
    conf.setEnum(SMART_REST_SERVER_LDAP_USER_SEARCH_SCOPE, LdapSearchScope.SUBTREE);

    conf.set(TEST_PARAM_NAME_OPTION, "searchByName");
    return conf;
  }

  private static SmartConf passwordCompareWithPasswordEncoding(EncoderType defaultEncoder) {
    SmartConf conf = baseConf();
    conf.set(SMART_REST_SERVER_LDAP_AUTH_TYPE, PASSWORD_COMPARE.toString());
    conf.setEnum(SMART_REST_SERVER_LDAP_USER_SEARCH_SCOPE, LdapSearchScope.SUBTREE);
    conf.set(SMART_REST_SERVER_LDAP_PASSWORD_ENCODER, defaultEncoder.getId());

    conf.set(TEST_PARAM_NAME_OPTION, "passwordCompareWithPasswordEncoding");
    return conf;
  }

  private static SmartConf searchByCustomSearch(AuthType authType) {
    SmartConf conf = baseConf();
    conf.set(SMART_REST_SERVER_LDAP_AUTH_TYPE, authType.toString());
    conf.set(SMART_REST_SERVER_LDAP_USER_SEARCH_BASE, "ou=people");
    conf.set(SMART_REST_SERVER_LDAP_CUSTOM_SEARCH, "(&(additionalAttr=test)(objectClass=person))");

    conf.set(TEST_PARAM_NAME_OPTION, "searchByCustomSearch");
    return conf;
  }

  private static SmartConf searchByCustomSearchSeveralUsers(AuthType authType) {
    SmartConf conf = baseConf();
    conf.set(SMART_REST_SERVER_LDAP_AUTH_TYPE, authType.toString());
    conf.set(SMART_REST_SERVER_LDAP_USER_SEARCH_BASE, "ou=people");
    conf.set(SMART_REST_SERVER_LDAP_CUSTOM_SEARCH, "(objectClass=person)");

    conf.set(TEST_PARAM_NAME_OPTION, "searchByCustomSearch");
    return conf;
  }

  private static SmartConf searchByGroupMemberAttr(AuthType authType, String groupName) {
    SmartConf conf = baseConf();
    conf.set(SMART_REST_SERVER_LDAP_AUTH_TYPE, authType.toString());
    conf.set(SMART_REST_SERVER_LDAP_USER_SEARCH_SCOPE, LdapSearchScope.SUBTREE.name());
    conf.set(SMART_REST_SERVER_LDAP_GROUP_OBJECT_DEFAULT, "groupOfNames");
    conf.set(SMART_REST_SERVER_LDAP_GROUP_MEMBER_ATTR, "member");
    conf.set(SMART_REST_SERVER_LDAP_GROUP_NAME_ATTR, "CN");
    conf.set(SMART_REST_SERVER_LDAP_USER_GROUPS, groupName);

    conf.set(TEST_PARAM_NAME_OPTION, "searchByGroupMemberAttr");
    return conf;
  }

  private static SmartConf searchByUserMemberAttr(AuthType authType, String groupName) {
    SmartConf conf = baseConf();
    conf.set(SMART_REST_SERVER_LDAP_AUTH_TYPE, authType.toString());
    conf.setEnum(SMART_REST_SERVER_LDAP_USER_SEARCH_SCOPE, LdapSearchScope.SUBTREE);
    conf.set(SMART_REST_SERVER_LDAP_USER_MEMBER_ATTR, "memberOf");
    conf.set(SMART_REST_SERVER_LDAP_GROUP_NAME_ATTR, "CN");
    conf.set(SMART_REST_SERVER_LDAP_USER_GROUPS, groupName);

    conf.set(TEST_PARAM_NAME_OPTION, "searchByUserMemberAttr");
    return conf;
  }

  private static SmartConf searchWithAdditionalSearch(AuthType authType) {
    SmartConf conf = searchByUserMemberAttr(authType, "developers");
    conf.set(SMART_REST_SERVER_LDAP_SEARCH_ADDITIONAL_FILTER, "(additionalAttr=test)");

    conf.set(TEST_PARAM_NAME_OPTION, "searchWithAdditionalSearch");
    return conf;
  }

  private static SmartConf baseConf() {
    SmartConf conf = new SmartConf();
    conf.setBoolean(LDAP_AUTH_ENABLED, true);
    conf.set(SMART_REST_SERVER_LDAP_URL, "ldap://localhost:" + LDAP_TEST_SERVER_PORT);
    conf.set(SMART_REST_SERVER_LDAP_SEARCH_BASE, "dc=ssm,dc=test");
    conf.set(SMART_REST_SERVER_LDAP_BIND_USER_DN, LDAP_BIND_DN);
    conf.set(SMART_REST_SERVER_LDAP_BIND_PASSWORD, LDAP_BIND_PASSWORD);
    return conf;
  }

  enum AuthType {
    BIND,
    PASSWORD_COMPARE
  }
}
