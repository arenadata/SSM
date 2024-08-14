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

import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.SearchableAbstractDao;
import org.smartdata.metastore.dao.FileAccessDao;
import org.smartdata.metastore.dao.FileInfoDao;
import org.smartdata.metastore.model.AggregatedAccessCounts;
import org.smartdata.metastore.queries.MetastoreQuery;
import org.smartdata.metastore.queries.sort.FileAccessInfoSortField;
import org.smartdata.model.FileAccessInfo;
import org.smartdata.model.request.FileAccessInfoSearchRequest;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.smartdata.metastore.queries.MetastoreQuery.select;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.betweenEpochInclusive;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.in;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.like;

public class DefaultFileAccessDao
    extends
    SearchableAbstractDao<FileAccessInfoSearchRequest, FileAccessInfo, FileAccessInfoSortField>
    implements FileAccessDao {

  public DefaultFileAccessDao(
      DataSource dataSource, PlatformTransactionManager transactionManager) {
    super(dataSource, transactionManager, TABLE_NAME);
  }

  @Override
  public void insert(Collection<AggregatedAccessCounts> aggregatedAccessCounts) {
    insert(new SimpleJdbcInsert(dataSource).withTableName(TABLE_NAME), aggregatedAccessCounts,
        this::toMap);
  }

  protected Map<String, Object> toMap(AggregatedAccessCounts accessCounts) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put(FileAccessDao.FILE_ID_FIELD, accessCounts.getFileId());
    parameters.put(FileAccessDao.ACCESS_TIME_FIELD,
        accessCounts.getLastAccessedTimestamp());
    return parameters;
  }

  @Override
  public void updateFileIds(long srcFileId, long destFileId) throws MetaStoreException {
    String statement = "UPDATE " + TABLE_NAME
        + " SET fid = " + destFileId
        + " WHERE fid = " + srcFileId;
    try {
      jdbcTemplate.execute(statement);
    } catch (Exception exception) {
      throw new MetaStoreException("Failed to update fid!", exception);
    }
  }

  @Override
  protected MetastoreQuery searchQuery(FileAccessInfoSearchRequest searchRequest) {
    return select("fid",
        "count",
        "access_time",
        "path")
        .fromSubQuery("SELECT file.fid, count(*) AS count,\n"
            + "MAX(file_access.access_time) as access_time, file.path as path\n"
            + "FROM file_access\n"
            + "    JOIN file ON file_access.fid = file.fid\n"
            + "GROUP BY file.fid, file.path", "f")
        .where(
            in("fid", searchRequest.getIds()),
            like("path", searchRequest.getPathLike()),
            betweenEpochInclusive("access_time",
                searchRequest.getLastAccessedTime())
        );
  }

  @Override
  protected FileAccessInfo mapRow(ResultSet rs, int rowNum) throws SQLException {
    return FileAccessInfo.builder()
        .setFid(rs.getLong(FileAccessDao.FILE_ID_FIELD))
        .setPath(rs.getString(FileInfoDao.FILE_PATH_FIELD))
        .setAccessCount(rs.getInt(FileAccessDao.ACCESS_COUNT_FIELD))
        .setLastAccessedTime(rs.getLong(FileAccessDao.ACCESS_TIME_FIELD))
        .build();
  }
}
