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

import org.smartdata.hive.rule.HmsSyncProgressDao;
import org.smartdata.metastore.dao.AbstractDao;

import javax.sql.DataSource;

import java.util.HashMap;
import java.util.Map;

public class PostgresHmsSyncProgressDao extends AbstractDao implements HmsSyncProgressDao {
  private static final String RULE_ID_FIELD = "rule_id";
  private static final String LAST_EVENT_ID_FIELD = "event_id";

  private final PostgresInsertSupport postgresInsertSupport;

  public PostgresHmsSyncProgressDao(DataSource dataSource) {
    super(dataSource, TABLE_NAME);
    this.postgresInsertSupport = new PostgresInsertSupport(dataSource, TABLE_NAME);
  }

  @Override
  public void insertIfNotPresent(long ruleId, long lastHandledEventId) {
    postgresInsertSupport.insertIfNotPresent(
        toNamedParameters(ruleId, lastHandledEventId), RULE_ID_FIELD);
  }

  @Override
  public void upsert(Map<Long, Long> ruleProgress) {
    postgresInsertSupport.batchUpsert(ruleProgress.entrySet(),
        this::toNamedParameters, RULE_ID_FIELD);
  }

  private Map<String, Object> toNamedParameters(Map.Entry<Long, Long> ruleProgress) {
    return toNamedParameters(ruleProgress.getKey(), ruleProgress.getValue());
  }

  private Map<String, Object> toNamedParameters(long ruleId, long lastHandledEventId) {
    Map<String, Object> namedParameters = new HashMap<>();
    namedParameters.put(RULE_ID_FIELD, ruleId);
    namedParameters.put(LAST_EVENT_ID_FIELD, lastHandledEventId);
    return namedParameters;
  }
}
