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

import org.smartdata.metastore.dao.impl.DefaultActionDao;
import org.smartdata.model.ActionInfo;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;

import java.util.List;

public class PostgresActionDao extends DefaultActionDao {
  private static final String PRIMARY_KEY_FIELD = "aid";

  private final PostgresInsertSupport upsertSupport;

  public PostgresActionDao(
      DataSource dataSource,
      PlatformTransactionManager transactionManager) {
    super(dataSource, transactionManager);
    this.upsertSupport = new PostgresInsertSupport(dataSource, tableName);
  }

  @Override
  public void upsert(List<ActionInfo> actionInfos) {
    upsertSupport.batchUpsert(actionInfos, this::toMap, PRIMARY_KEY_FIELD);
  }
}
