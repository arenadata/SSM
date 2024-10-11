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
package org.smartdata.server.config;

import org.smartdata.server.config.ldap.search.LdapSearchScope;

import java.util.Collections;
import java.util.List;

public class ConfigKeys {
  public static final String WEB_SECURITY_ENABLED = "smart.rest.server.security.enabled";

  public static final String SPNEGO_AUTH_ENABLED = "smart.rest.server.auth.spnego.enabled";

  public static final String KERBEROS_BASIC_AUTH_ENABLED =
      "smart.rest.server.auth.kerberos.enabled";

  public static final String PREDEFINED_BASIC_AUTH_ENABLED =
      "smart.rest.server.auth.predefined.enabled";

  public static final String PREDEFINED_USERS = "smart.rest.server.auth.predefined.users";

  public static final String SMART_REST_SERVER_KEYTAB_FILE_KEY =
      "smart.rest.server.auth.spnego.keytab";

  public static final String SMART_REST_SERVER_KERBEROS_PRINCIPAL =
      "smart.rest.server.auth.spnego.principal";

  public static final String SSL_ENABLED = "smart.rest.server.ssl.enabled";
  public static final boolean SSL_ENABLED_DEFAULT = false;

  public static final String SSL_KEYSTORE_PATH = "smart.rest.server.ssl.keystore";

  public static final String SSL_KEYSTORE_PASSWORD = "smart.rest.server.ssl.keystore.password";

  public static final String SSL_KEY_PASSWORD = "smart.rest.server.ssl.key.password";

  public static final String SSL_KEY_ALIAS = "smart.rest.server.ssl.key.alias";

  public static final String LDAP_AUTH_ENABLED =
      "smart.rest.server.auth.ldap.enabled";

  public static final String SMART_REST_SERVER_LDAP_SEARCH_BASE =
      "smart.rest.server.auth.ldap.search.base";

  public static final String SMART_REST_SERVER_LDAP_SEARCH_BASE_DEFAULT =
      "";

  public static final String SMART_REST_SERVER_LDAP_URL =
      "smart.rest.server.auth.ldap.url";

  public static final String SMART_REST_SERVER_LDAP_USER_SEARCH_BASE =
      "smart.rest.server.auth.ldap.user.search.base";

  public static final String SMART_REST_SERVER_LDAP_GROUP_SEARCH_BASE =
      "smart.rest.server.auth.ldap.group.search.base";

  public static final String SMART_REST_SERVER_LDAP_USER_NAME_ATTR =
      "smart.rest.server.auth.ldap.user.attributes.name";

  public static final String SMART_REST_SERVER_LDAP_USER_NAME_ATTR_DEFAULT =
      "uid";

  public static final String SMART_REST_SERVER_LDAP_USER_OBJECT =
      "smart.rest.server.auth.ldap.user.object-classes";

  public static final List<String> SMART_REST_SERVER_LDAP_USER_OBJECT_DEFAULT =
      Collections.singletonList("person");

  public static final String SMART_REST_SERVER_LDAP_SEARCH_ADDITIONAL_FILTER =
      "smart.rest.server.auth.ldap.user.search.additional.filter";

  public static final String SMART_REST_SERVER_LDAP_USER_SEARCH_SCOPE =
      "smart.rest.server.auth.ldap.user.search.scope";

  public static final LdapSearchScope SMART_REST_SERVER_LDAP_USER_SEARCH_SCOPE_DEFAULT =
      LdapSearchScope.ONE_LEVEL;

  public static final String SMART_REST_SERVER_LDAP_GROUP_SEARCH_SCOPE =
      "smart.rest.server.auth.ldap.group.search.scope";

  public static final LdapSearchScope SMART_REST_SERVER_LDAP_GROUP_SEARCH_SCOPE_DEFAULT =
      LdapSearchScope.ONE_LEVEL;

  public static final String SMART_REST_SERVER_LDAP_CUSTOM_SEARCH =
      "smart.rest.server.auth.ldap.user.search.filter";

  public static final String SMART_REST_SERVER_LDAP_USER_MEMBER_ATTR =
      "smart.rest.server.auth.ldap.user.attributes.membership";
  public static final String SMART_REST_SERVER_LDAP_USER_MEMBER_ATTR_DEFAULT =
      "memberOf";

  public static final String SMART_REST_SERVER_LDAP_USER_PASSWORD_ATTR =
      "smart.rest.server.auth.ldap.user.attributes.password";

  public static final String SMART_REST_SERVER_LDAP_USER_PASSWORD_ATTR_DEFAULT =
      "userPassword";

  public static final String SMART_REST_SERVER_LDAP_USER_GROUPS =
      "smart.rest.server.auth.ldap.user.search.groups";

  public static final String SMART_REST_SERVER_LDAP_GROUP_OBJECT =
      "smart.rest.server.auth.ldap.group.object-class";

  public static final String SMART_REST_SERVER_LDAP_GROUP_OBJECT_DEFAULT =
      "groupOfNames";

  public static final String SMART_REST_SERVER_LDAP_GROUP_MEMBER_ATTR =
      "smart.rest.server.auth.ldap.group.attributes.member";

  public static final String SMART_REST_SERVER_LDAP_GROUP_MEMBER_DEFAULT =
      "member";

  public static final String SMART_REST_SERVER_LDAP_GROUP_NAME_ATTR =
      "smart.rest.server.auth.ldap.group.attributes.name";

  public static final String SMART_REST_SERVER_LDAP_GROUP_NAME_DEFAULT =
      "cn";

  public static final String SMART_REST_SERVER_LDAP_AUTH_TYPE =
      "smart.rest.server.auth.ldap.auth.type";

  public static final String SMART_REST_SERVER_LDAP_BIND_USER_DN =
      "smart.rest.server.auth.ldap.bind.user";

  public static final String SMART_REST_SERVER_LDAP_BIND_PASSWORD =
      "smart.rest.server.auth.ldap.bind.password";

  public static final String SMART_REST_SERVER_AUTH_ERRORS_LOGGING_ENABLED =
      "smart.rest.server.auth.failures.logging.enabled";
}
