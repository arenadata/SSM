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

import org.apache.hadoop.conf.Configuration;
import org.smartdata.metastore.DBPool;
import org.smartdata.metastore.DBType;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.db.metadata.DbMetadataProvider;
import org.smartdata.metastore.db.metadata.PostgresDbMetadataProvider;

import javax.sql.DataSource;

import static org.smartdata.conf.SmartConfKeys.SMART_METASTORE_MIGRATION_CHANGELOG_PATH_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_METASTORE_MIGRATION_CHANGELOG_PATH_KEY;

public class DBHandlersFactory {

  public DbSchemaManager createDbManager(DBPool dbPool, Configuration conf) {
    String changelogPath = conf.get(
        SMART_METASTORE_MIGRATION_CHANGELOG_PATH_KEY,
        SMART_METASTORE_MIGRATION_CHANGELOG_PATH_DEFAULT);
    return new LiquibaseDbSchemaManager(dbPool, changelogPath);
  }

  public DbMetadataProvider createDbMetadataProvider(DBPool dbPool, DBType dbType)
      throws MetaStoreException {
    DataSource dataSource = dbPool.getDataSource();
    switch (dbType) {
      case POSTGRES:
      default:
        return new PostgresDbMetadataProvider(dataSource);
    }
  }
}
