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
package org.smartdata.metastore.dao.impl;

import org.smartdata.ozone.OzoneFileInfoDao;
import org.smartdata.ozone.model.OzoneFileInfo;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;

import javax.sql.DataSource;

import java.util.HashMap;
import java.util.Map;

public class DefaultOzoneFileInfoDao extends BaseFileInfoDao implements OzoneFileInfoDao {
  private static final String TABLE_NAME = "ofile";

  private static final String FILE_ID_FIELD = "fid";
  private static final String PATH_FIELD = "path";
  private static final String LENGTH_FIELD = "length";
  private static final String BLOCK_REPLICATION_FIELD = "block_replication";
  private static final String BLOCK_SIZE_FIELD = "block_size";
  private static final String MODIFICATION_TIME_FIELD = "modification_time";
  private static final String ACCESS_TIME_FIELD = "access_time";
  private static final String IS_VOLUME_FIELD = "is_volume";
  private static final String IS_BUCKET_FIELD = "is_bucket";
  private static final String IS_S3_FIELD = "is_s3";
  private static final String OWNER_FIELD = "owner";
  private static final String OWNER_GROUP_FIELD = "owner_group";
  private static final String PERMISSION_FIELD = "permission";
  private static final String EC_POLICY_FIELD = "ec_policy";

  public DefaultOzoneFileInfoDao(DataSource dataSource) {
    super(dataSource, TABLE_NAME);
  }

  @Override
  public void insert(OzoneFileInfo fileInfo) {
    insert(fileInfo, this::toMap);
  }

  @Override
  protected SimpleJdbcInsert simpleJdbcInsert() {
    return super.simpleJdbcInsert()
        .usingGeneratedKeyColumns(FILE_ID_FIELD);
  }

  private Map<String, Object> toMap(OzoneFileInfo fileInfo) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put(PATH_FIELD, fileInfo.getPath());
    parameters.put(LENGTH_FIELD, fileInfo.getLength());
    parameters.put(BLOCK_REPLICATION_FIELD, fileInfo.getBlockReplication());
    parameters.put(BLOCK_SIZE_FIELD, fileInfo.getBlockSize());
    parameters.put(MODIFICATION_TIME_FIELD, fileInfo.getModificationTime());
    parameters.put(ACCESS_TIME_FIELD, fileInfo.getAccessTime());
    parameters.put(IS_VOLUME_FIELD, fileInfo.isVolume());
    parameters.put(IS_BUCKET_FIELD, fileInfo.isBucket());
    parameters.put(IS_S3_FIELD, fileInfo.isS3());
    parameters.put(OWNER_FIELD, fileInfo.getOwner());
    parameters.put(OWNER_GROUP_FIELD, fileInfo.getGroup());
    parameters.put(PERMISSION_FIELD, fileInfo.getPermission());
    parameters.put(EC_POLICY_FIELD, fileInfo.getErasureCodingPolicy());
    return parameters;
  }
}
