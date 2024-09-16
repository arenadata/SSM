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
package org.smartdata.metastore.dao;

import org.apache.commons.lang3.ArrayUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;

import javax.sql.DataSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

/** Contains common methods for DAOs. */
public class AbstractDao {
  protected final DataSource dataSource;
  protected final JdbcTemplate jdbcTemplate;
  protected final String tableName;

  public AbstractDao(DataSource dataSource, String tableName) {
    this.dataSource = dataSource;
    this.jdbcTemplate = new JdbcTemplate(dataSource);
    this.tableName = tableName;
  }

  protected SimpleJdbcInsert simpleJdbcInsert() {
    return new SimpleJdbcInsert(dataSource)
        .withTableName(tableName);
  }

  protected <T> void insert(T entity, EntityToMapConverter<T> converter) {
    SimpleJdbcInsert simpleJdbcInsert = simpleJdbcInsert();
    simpleJdbcInsert.execute(converter.toMap(entity));
  }

  protected <T> void insert(T[] entities, EntityToMapConverter<T> converter) {
    insert(Arrays.asList(entities), converter);
  }

  protected <T> void insert(Collection<T> entities, EntityToMapConverter<T> converter) {
    insert(simpleJdbcInsert(), entities, converter);
  }

  @SuppressWarnings("unchecked")
  protected <T> void insert(
      SimpleJdbcInsert simpleJdbcInsert,
      Collection<T> entities,
      EntityToMapConverter<T> converter) {
    Map<String, Object>[] maps = entities.stream()
        .map(converter::toMap)
        .toArray(Map[]::new);
    simpleJdbcInsert.executeBatch(maps);
  }

  protected int update(Map<String, Object> entityProperties,
                       String filter, Object... filterArguments) {
    return updateInternal(entityProperties, " WHERE " + filter, filterArguments);
  }

  protected int update(Map<String, Object> entityProperties) {
    return updateInternal(entityProperties, " ");
  }

  protected int updateInternal(Map<String, Object> entityProperties,
                               String filter, Object... filterArguments) {
    StringJoiner updateSql = new StringJoiner(", ", "UPDATE " + tableName + " SET ", filter);
    List<Object> setArguments = new ArrayList<>();

    for (Map.Entry<String, Object> property: entityProperties.entrySet()) {
      if (property.getValue() == null) {
        continue;
      }
      setArguments.add(property.getValue());
      updateSql.add(property.getKey() + " = ?");
    }

    if (setArguments.isEmpty()) {
      return 0;
    }

    Object[] argumentsArray = ArrayUtils.addAll(setArguments.toArray(), filterArguments);
    return jdbcTemplate.update(updateSql.toString(), argumentsArray);
  }

  protected interface EntityToMapConverter<T> {
    Map<String, Object> toMap(T entity);
  }
}
