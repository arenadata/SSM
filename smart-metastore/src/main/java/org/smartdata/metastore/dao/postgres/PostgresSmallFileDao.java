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

import org.smartdata.metastore.dao.impl.DefaultSmallFileDao;
import org.smartdata.model.CompactFileState;
import org.smartdata.model.FileContainerInfo;

import javax.sql.DataSource;

import java.util.HashMap;
import java.util.Map;

public class PostgresSmallFileDao extends DefaultSmallFileDao {
  private static final String PRIMARY_KEY_FIELD = "path";

  private final PostgresInsertSupport upsertSupport;

  public PostgresSmallFileDao(DataSource dataSource) {
    super(dataSource);
    this.upsertSupport = new PostgresInsertSupport(dataSource, tableName);
  }

  @Override
  public void insertUpdate(CompactFileState compactFileState) {
    upsertSupport.upsert(toNamedParameters(compactFileState), PRIMARY_KEY_FIELD);
  }

  @Override
  public int[] batchInsertUpdate(CompactFileState[] fileStates) {
    return upsertSupport.batchUpsert(fileStates,
        this::toNamedParameters, PRIMARY_KEY_FIELD);
  }

  private Map<String, Object> toNamedParameters(CompactFileState fileState) {
    FileContainerInfo containerInfo = fileState.getFileContainerInfo();

    Map<String, Object> namedParameters = new HashMap<>();
    namedParameters.put("path", fileState.getPath());
    namedParameters.put("container_file_path", containerInfo.getContainerFilePath());
    namedParameters.put("file_offset", containerInfo.getOffset());
    namedParameters.put("length", containerInfo.getLength());
    return namedParameters;
  }
}
