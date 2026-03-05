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
package org.smartdata.test.service;

import io.qameta.allure.Step;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.jdbc.datasource.init.ScriptUtils;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;

import java.sql.Connection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;

@Service
public class SqlExecutor {
  @Step("Execute SQL script")
  public void executeSql(DataSource dataSource, String sql) {
    Connection conn = DataSourceUtils.getConnection(dataSource);
    try {
      ByteArrayResource resource = new ByteArrayResource(sql.getBytes(UTF_8));
      EncodedResource encodedResource = new EncodedResource(resource, UTF_8);
      ScriptUtils.executeSqlScript(conn, encodedResource);
    } finally {
      DataSourceUtils.releaseConnection(conn, dataSource);
    }
  }

  @Step("Execute SQL file by path '{path}'")
  public void executeSqlFile(DataSource dataSource, String path) {
    Connection conn = DataSourceUtils.getConnection(dataSource);
    try {
      ScriptUtils.executeSqlScript(conn, new FileSystemResource(path));
    } finally {
      DataSourceUtils.releaseConnection(conn, dataSource);
    }
  }

  @Step("Query list by SQL")
  public List<Map<String, Object>> queryForList(DataSource dataSource, String sql) {
    JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
    return jdbcTemplate.queryForList(sql);
  }

  @Step("Query first column as strings by SQL")
  public List<String> queryFirstColumnAsStrings(DataSource dataSource, String sql) {
    return queryForList(dataSource, sql).stream()
        .map(row -> row.values().iterator().next())
        .filter(Objects::nonNull)
        .map(Object::toString)
        .collect(Collectors.toList());
  }

  @Step("Query column '{columnName}' as strings by SQL")
  public List<String> queryByColumnAsStrings(DataSource dataSource, String sql, String columnName) {
    return queryForList(dataSource, sql).stream()
        .map(row -> row.get(columnName))
        .filter(Objects::nonNull)
        .map(Object::toString)
        .collect(Collectors.toList());
  }
}
