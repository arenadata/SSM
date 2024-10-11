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

import org.smartdata.server.config.ldap.search.query.LdapExpressionTemplate;
import org.springframework.ldap.support.LdapEncoder;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import java.text.MessageFormat;
import java.util.Collection;

import static org.smartdata.server.config.ldap.search.query.LdapQueryDsl.eq;
import static org.smartdata.server.config.ldap.search.query.LdapQueryDsl.or;
import static org.springframework.ldap.support.LdapUtils.removeFirst;

public class LdapUtils {
  private static final String OBJECT_CLASS_ATTRIBUTE = "objectClass";

  public static LdapExpressionTemplate isClassObject(Collection<String> objectClasses) {
    return or(
        objectClasses.stream()
            .map(LdapUtils::isClassObject)
            .toArray(LdapExpressionTemplate[]::new)
    );
  }

  public static LdapExpressionTemplate isClassObject(String objectClass) {
    return eq(OBJECT_CLASS_ATTRIBUTE, objectClass);
  }

  public static String formatTemplate(LdapExpressionTemplate template, Object... args) {
    Object[] encodedParams = new String[args.length];
    for (int i = 0; i < args.length; i++) {
      encodedParams[i] = LdapEncoder.filterEncode(args[i].toString());
    }
    return MessageFormat.format(template.build(), encodedParams);
  }

  public static LdapName getRelativeBaseName(String searchBaseName, LdapName ctxBaseLdapName) {
    try {
      LdapName searchBaseLdapName = new LdapName(searchBaseName);
      return removeFirst(searchBaseLdapName, ctxBaseLdapName);
    } catch (InvalidNameException e) {
      throw new IllegalArgumentException("Error building LDAP name from: " + searchBaseName, e);
    }
  }
}
