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

import org.apache.commons.collections.CollectionUtils;
import org.smartdata.model.TimeInterval;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.smartdata.utils.DateTimeUtils.intervalEndToEpoch;
import static org.smartdata.utils.DateTimeUtils.intervalStartToEpoch;

/**
 * DSL for convenient writing of SQL queries with multiple
 * (possibly optional) filters. if null value is provided
 * to any of the operator constructor methods, then such operator will be ignored.
 * */
public class MetastoreQueryDsl {

  private static final MetastoreQueryExpression EMPTY_EXPRESSION = () -> "";

  public static MetastoreQueryExpression emptyExpression() {
    return EMPTY_EXPRESSION;
  }

  public static MetastoreQueryExpression or(MetastoreQueryExpression... expressions) {
    return operator("OR", expressions);
  }

  public static MetastoreQueryExpression and(MetastoreQueryExpression... expressions) {
    return operator("AND", expressions);
  }

  public static <T> MetastoreQueryExpression greaterThan(String column, T value) {
    return binaryOpWithPlaceholder(">", column, value);
  }

  public static <T> MetastoreQueryExpression greaterThanEqual(String column, T value) {
    return binaryOpWithPlaceholder(">=", column, value);
  }

  public static <T> MetastoreQueryExpression lessThan(String column, T value) {
    return binaryOpWithPlaceholder("<", column, value);
  }

  public static <T> MetastoreQueryExpression lessThanEqual(String column, T value) {
    return binaryOpWithPlaceholder("<=", column, value);
  }

  public static <T> MetastoreQueryExpression equal(String column, T value) {
    return binaryOpWithPlaceholder("=", column, value);
  }

  public static MetastoreQueryExpression isNull(String column) {
    return binaryOpWithLiteralArgs("is", column, "NULL");
  }

  public static MetastoreQueryExpression isNotNull(String column) {
    return binaryOpWithLiteralArgs("is", column, "NOT NULL");
  }

  public static <T> MetastoreQueryExpression in(String column, List<T> values) {
    if (CollectionUtils.isEmpty(values)) {
      return emptyExpression();
    }

    if (values.size() == 1) {
      return equal(column, values.get(0));
    }

    return binaryOpWithPlaceholder("IN", column, values);
  }

  public static <T> MetastoreQueryExpression inStrings(String column, List<T> values) {
    if (CollectionUtils.isEmpty(values)) {
      return emptyExpression();
    }

    List<String> strValues = values.stream()
        .map(Object::toString)
        .collect(Collectors.toList());

    return in(column, strValues);
  }

  public static <T> MetastoreQueryExpression between(String column, T from, T to) {
    return and(
        greaterThan(column, from),
        lessThan(column, to)
    );
  }

  public static <T> MetastoreQueryExpression betweenInclusive(String column, T from, T to) {
    return and(
        greaterThanEqual(column, from),
        lessThanEqual(column, to)
    );
  }

  public static MetastoreQueryExpression betweenEpoch(
      String column, TimeInterval timeInterval) {
    Long from = intervalStartToEpoch(timeInterval);
    Long to = intervalEndToEpoch(timeInterval);

    return between(column, from, to);
  }

  public static MetastoreQueryExpression betweenEpochInclusive(
      String column, TimeInterval timeInterval) {
    Long from = intervalStartToEpoch(timeInterval);
    Long to = intervalEndToEpoch(timeInterval);

    return betweenInclusive(column, from, to);
  }

  public static <T> MetastoreQueryExpression like(String column, T value) {
    return patternSearchOp("LIKE", column, value);
  }

  public static <T> MetastoreQueryExpression notLike(String column, T value) {
    return patternSearchOp("NOT LIKE", column, value);
  }

  private static <T> MetastoreQueryExpression patternSearchOp(
      String operator, String column, T value) {
    return Optional.ofNullable(value)
        .map(val -> binaryOpWithPlaceholder(operator, column, "%" + val + "%"))
        .orElseGet(MetastoreQueryDsl::emptyExpression);
  }

  private static MetastoreQueryExpression operator(
      String operator, MetastoreQueryExpression... expressions) {
    List<MetastoreQueryExpression> nonEmptyExpressions = Arrays.stream(expressions)
        .filter(expression -> !EMPTY_EXPRESSION.equals(expression))
        .collect(Collectors.toList());

    if (nonEmptyExpressions.isEmpty()) {
      return emptyExpression();
    }

    return new MetastoreQueryOperator(operator, nonEmptyExpressions);
  }

  private static <T> MetastoreQueryExpression binaryOpWithPlaceholder(
      String operator, String column, T value) {
    if (value == null) {
      return emptyExpression();
    }

    return new MetastoreQueryOperator(operator,
        Arrays.asList(
            literal(column),
            new MetastoreQueryPlaceholder<>(column, value)
        )
    );
  }

  private static MetastoreQueryExpression binaryOpWithLiteralArgs(
      String operator, String... args) {
    return new MetastoreQueryOperator(operator,
        Arrays.stream(args)
            .map(MetastoreQueryDsl::literal)
            .collect(Collectors.toList())
    );
  }

  private static MetastoreQueryExpression literal(String literal) {
    return () -> literal;
  }
}
