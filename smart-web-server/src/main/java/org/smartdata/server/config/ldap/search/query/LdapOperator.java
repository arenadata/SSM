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

import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Data
@RequiredArgsConstructor
public class LdapOperator implements LdapExpressionTemplate {
  private final String operator;
  private final List<LdapExpressionTemplate> arguments;

  public LdapOperator(String operator, LdapExpressionTemplate... arguments) {
    this(operator, Arrays.asList(arguments));
  }

  @Override
  public String build() {
    if (arguments.size() == 1) {
      return arguments.get(0).build();
    }

    return "("
        + operator
        + arguments.stream()
        .filter(expr -> !expr.isEmpty())
        .flatMap(this::maybeFlattenOperators)
        .map(LdapExpressionTemplate::build)
        .collect(Collectors.joining(""))
        + ")";
  }

  private Stream<LdapExpressionTemplate> maybeFlattenOperators(
      LdapExpressionTemplate template) {
    if (!(template instanceof LdapOperator)) {
      return Stream.of(template);
    }

    LdapOperator other = (LdapOperator) template;
    return operator.equals(other.operator)
        ? other.arguments.stream()
        : Stream.of(template);
  }
}
