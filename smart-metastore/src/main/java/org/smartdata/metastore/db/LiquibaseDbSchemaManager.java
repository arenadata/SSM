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
package org.smartdata.metastore.db;

import liquibase.Scope;
import liquibase.command.CommandScope;
import liquibase.command.core.DropAllCommandStep;
import liquibase.command.core.UpdateCommandStep;
import liquibase.command.core.helpers.DbUrlConnectionCommandStep;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;
import liquibase.ui.LoggerUIService;
import org.smartdata.metastore.DBPool;

import java.sql.Connection;
import java.util.HashMap;
import java.util.Map;

public class LiquibaseDbSchemaManager implements DbSchemaManager {
  private final DBPool pool;
  private final String changelogPath;

  private final Map<String, Object> scopeConfig;

  public LiquibaseDbSchemaManager(DBPool pool, String changelogPath) {
    this.pool = pool;
    this.changelogPath = changelogPath;
    this.scopeConfig = new HashMap<>();

    scopeConfig.put(Scope.Attr.ui.name(), new LoggerUIService());
  }

  @Override
  public void initializeDatabase() throws Exception {
    try (Connection connection = pool.getConnection();
         JdbcConnection jdbcConnection = new JdbcConnection(connection)) {
      Database db = DatabaseFactory.getInstance()
          .findCorrectDatabaseImplementation(jdbcConnection);

      CommandScope updateCommand = new CommandScope(UpdateCommandStep.COMMAND_NAME)
          .addArgumentValue(DbUrlConnectionCommandStep.DATABASE_ARG, db)
          .addArgumentValue(UpdateCommandStep.CHANGELOG_FILE_ARG, changelogPath);

      executeWithLogging(updateCommand);
    }
  }

  @Override
  public void clearDatabase() throws Exception {
    try (Connection connection = pool.getConnection();
         JdbcConnection jdbcConnection = new JdbcConnection(connection)) {
      Database db = DatabaseFactory.getInstance()
          .findCorrectDatabaseImplementation(jdbcConnection);

      CommandScope dropAllCommand = new CommandScope(DropAllCommandStep.COMMAND_NAME)
          .addArgumentValue(DbUrlConnectionCommandStep.DATABASE_ARG, db);
      executeWithLogging(dropAllCommand);
    }
  }

  private void executeWithLogging(CommandScope commandScope) throws Exception {
    Scope.child(scopeConfig, commandScope::execute);
  }
}
