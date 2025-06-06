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
package org.smartdata.metastore.queries.expression;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class MetastoreQueryOperator implements MetastoreQueryExpression {
  private static final String REPLACED_PARAM_PREFIX = "$_";

  protected final String operator;
  protected final List<MetastoreQueryExpression> args;

  private final Set<String> argParamNames;
  private int paramNameCounter;

  public MetastoreQueryOperator(String operator, List<MetastoreQueryExpression> args) {
    this.operator = operator;
    this.args = args;
    this.argParamNames = new HashSet<>();
    this.paramNameCounter = 0;

    args.forEach(this::maybeUpdateArgParams);
  }

  @Override
  public String build() {
    return args.stream()
        .map(MetastoreQueryExpression::build)
        .collect(Collectors.joining(" " + operator + " ", "(", ")"));
  }

  @Override
  public Map<String, Object> getParameters() {
    return args.stream()
        .map(arg -> arg.getParameters().entrySet())
        .flatMap(Set::stream)
        .collect(Collectors.toMap(
            Map.Entry::getKey,
            Map.Entry::getValue
        ));
  }

  @Override
  public void renameParameter(String oldName, String newName) {
    args.forEach(expression -> expression.renameParameter(oldName, newName));
  }

  private void maybeUpdateArgParams(MetastoreQueryExpression expression) {
    Set<String> expressionParams = expression.getParameters().keySet();
    new HashSet<>(expressionParams)
        .stream()
        .filter(argParamNames::contains)
        .forEach(param -> updateExpressionParam(expression, param));

    argParamNames.addAll(expressionParams);
  }

  private void updateExpressionParam(MetastoreQueryExpression expression, String param) {
    String newParamNamePrefix = REPLACED_PARAM_PREFIX + param;
    String newParamName;

    do {
      ++paramNameCounter;
      newParamName = newParamNamePrefix + paramNameCounter;
    } while (argParamNames.contains(newParamName));

    expression.renameParameter(param, newParamName);
  }
}
