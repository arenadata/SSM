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

  public static final String SSL_ENABLED = "smart.rest.server.ssl.enabled";
  public static final boolean SSL_ENABLED_DEFAULT = false;

  public static final String SSL_KEYSTORE_PATH = "smart.rest.server.ssl.keystore";

  public static final String SSL_KEYSTORE_PASSWORD = "smart.rest.server.ssl.keystore.password";

  public static final String SSL_KEY_PASSWORD = "smart.rest.server.ssl.key.password";

  public static final String SSL_KEY_ALIAS = "smart.rest.server.ssl.key.alias";
}
