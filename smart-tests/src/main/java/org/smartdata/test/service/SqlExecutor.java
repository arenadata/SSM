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

import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.jdbc.datasource.init.ScriptUtils;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;

import java.sql.Connection;

import static java.nio.charset.StandardCharsets.UTF_8;

@Service
public class SqlExecutor {
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

  public void executeSqlFile(DataSource dataSource, String path) {
    Connection conn = DataSourceUtils.getConnection(dataSource);
    try {
      ScriptUtils.executeSqlScript(conn, new FileSystemResource(path));
    } finally {
      DataSourceUtils.releaseConnection(conn, dataSource);
    }
  }
}
