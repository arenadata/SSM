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
package org.smartdata.metastore.dao.postgres;

import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import javax.sql.DataSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class PostgresInsertSupport {
  private final NamedParameterJdbcTemplate namedJdbcTemplate;
  private final String tableName;

  public PostgresInsertSupport(DataSource dataSource, String tableName) {
    this.namedJdbcTemplate = new NamedParameterJdbcTemplate(dataSource);
    this.tableName = tableName;
  }

  public void insertIfNotPresent(Map<String, Object> namedParameters, String primaryKeyField) {
    String sqlTemplate = generateSqlTemplate(namedParameters, primaryKeyField, false);
    namedJdbcTemplate.update(sqlTemplate, namedParameters);
  }

  public void upsert(Map<String, Object> namedParameters, String primaryKeyField) {
    String sqlTemplate = generateSqlTemplate(namedParameters, primaryKeyField, true);
    namedJdbcTemplate.update(sqlTemplate, namedParameters);
  }

  public <T> int[] batchUpsert(
      Collection<T> entities,
      EntityToMapConverter<T> entityMapper,
      String primaryKeyField) {
    return batchUpsert(entities.stream(), entityMapper, primaryKeyField);
  }

  public <T> int[] batchUpsert(
      T[] entities,
      EntityToMapConverter<T> entityMapper,
      String primaryKeyField) {
    return batchUpsert(Arrays.stream(entities), entityMapper, primaryKeyField);
  }

  @SuppressWarnings("unchecked")
  private <T> int[] batchUpsert(
      Stream<T> entitiesStream,
      EntityToMapConverter<T> entityMapper,
      String primaryKeyField) {
    Map<String, Object>[] namedParameters = entitiesStream
        .map(entityMapper::toMap)
        .toArray(Map[]::new);
    return batchUpsert(namedParameters, primaryKeyField);
  }

  private int[] batchUpsert(Map<String, Object>[] namedParameters, String primaryKeyField) {
    if (namedParameters.length == 0) {
      return new int[0];
    }
    String sqlTemplate = generateSqlTemplate(namedParameters[0], primaryKeyField, true);
    return namedJdbcTemplate.batchUpdate(sqlTemplate, namedParameters);
  }

  String generateSqlTemplate(
      Map<String, Object> namedParameters,
      String primaryKeyField,
      boolean updateFieldsIfFound
  ) {
    ArrayList<String> fieldNames = new ArrayList<>(namedParameters.keySet());

    String valueFieldsClause = String.join(", ", fieldNames);

    String valuesClause = fieldNames
        .stream()
        .map(field -> ":" + field)
        .collect(Collectors.joining(",\n"));

    String baseQuery =
        "INSERT INTO "
            + tableName
            + "("
            + valueFieldsClause
            + ")\n"
            + "VALUES ("
            + valuesClause
            + ")\n"
            + "ON CONFLICT ("
            + primaryKeyField
            + ")\n";

    if (!updateFieldsIfFound) {
      return baseQuery + "DO NOTHING";
    }

    String setClause = fieldNames
        .stream()
        .map(field -> String.format("%s = :%s", field, field))
        .collect(Collectors.joining(",\n"));

    return baseQuery
        + "DO UPDATE SET "
        + setClause;
  }

  public interface EntityToMapConverter<T> {
    Map<String, Object> toMap(T entity);
  }
}
