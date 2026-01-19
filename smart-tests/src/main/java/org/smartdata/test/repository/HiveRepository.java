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
package org.smartdata.test.repository;

import io.arenadata.test.util.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

@Repository
public class HiveRepository {

  @Autowired
  private DataSource hiveDataSource;

  public Connection getConnection() throws SQLException {
    return hiveDataSource.getConnection();
  }

  public void executeSql(String sql) throws SQLException {
    try (Connection connection = hiveDataSource.getConnection();
         Statement statement = connection.createStatement()) {
      statement.execute(sql);
    }
  }

  public void executeSqlFile(String path) throws SQLException {
    String sql = FileUtils.readFile(path);
    executeSql(sql);
  }
}
