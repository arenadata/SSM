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

import org.smartdata.metastore.dao.impl.DefaultFileStateDao;
import org.smartdata.model.FileState;

import javax.sql.DataSource;

import java.util.HashMap;
import java.util.Map;

public class PostgresFileStateDao extends DefaultFileStateDao {
  private static final String PRIMARY_KEY_FIELD = "path";

  private final PostgresInsertSupport upsertSupport;

  public PostgresFileStateDao(DataSource dataSource) {
    super(dataSource);
    this.upsertSupport = new PostgresInsertSupport(dataSource, tableName);
  }

  @Override
  public void insertUpdate(FileState fileState) {
    upsertSupport.upsert(toNamedParameters(fileState), PRIMARY_KEY_FIELD);
  }

  @Override
  public int[] batchInsertUpdate(FileState[] fileStates) {
    return upsertSupport.batchUpsert(fileStates,
        this::toNamedParameters, PRIMARY_KEY_FIELD);
  }

  private Map<String, Object> toNamedParameters(FileState fileState) {
    Map<String, Object> namedParameters = new HashMap<>();
    namedParameters.put("path", fileState.getPath());
    namedParameters.put("type", fileState.getFileType().getValue());
    namedParameters.put("stage", fileState.getFileStage().getValue());
    return namedParameters;
  }
}
