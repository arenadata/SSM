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
package org.smartdata.server.config.ldap.search.query;

import java.util.List;

public class LdapQueryDsl {
  public static LdapExpressionTemplate and(LdapExpressionTemplate... expressions) {
    return new LdapOperator("&", expressions);
  }

  public static LdapExpressionTemplate and(List<LdapExpressionTemplate> expressions) {
    return new LdapOperator("&", expressions);
  }

  public static LdapExpressionTemplate or(LdapExpressionTemplate... expressions) {
    return new LdapOperator("|", expressions);
  }

  public static LdapExpressionTemplate not(LdapExpressionTemplate expression) {
    return new LdapOperator("!", expression);
  }

  public static LdapExpressionTemplate eq(String attribute, Object value) {
    return new LdapFilter("=", attribute, value);
  }
}
