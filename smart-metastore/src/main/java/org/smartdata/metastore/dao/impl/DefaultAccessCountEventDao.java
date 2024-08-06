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

import com.google.common.collect.ImmutableMap;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.SearchableAbstractDao;
import org.smartdata.metastore.dao.FileInfoDao;
import org.smartdata.metastore.dao.accesscount.AccessCountEventDao;
import org.smartdata.metastore.model.AccessCountTable;
import org.smartdata.metastore.model.AggregatedAccessCounts;
import org.smartdata.metastore.queries.MetastoreQuery;
import org.smartdata.metastore.queries.MetastoreQueryExecutor;
import org.smartdata.metastore.queries.sort.FileAccessInfoSortField;
import org.smartdata.model.FileAccessInfo;
import org.smartdata.model.request.FileAccessInfoSearchRequest;
import org.springframework.jdbc.core.ColumnMapRowMapper;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.smartdata.metastore.queries.MetastoreQuery.select;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.betweenEpochInclusive;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.in;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.like;

public class DefaultAccessCountEventDao
    extends
    SearchableAbstractDao<FileAccessInfoSearchRequest, FileAccessInfo, FileAccessInfoSortField>
    implements AccessCountEventDao {

  private static final String TABLE_NAME = "access_count_table";
  private final MetastoreQueryExecutor queryExecutor;

  public DefaultAccessCountEventDao(
      DataSource dataSource, PlatformTransactionManager transactionManager) {
    super(dataSource, transactionManager, TABLE_NAME);

    this.queryExecutor = new MetastoreQueryExecutor(dataSource, transactionManager);
  }

  @Override
  public void insert(AccessCountTable table,
                     Collection<AggregatedAccessCounts> aggregatedAccessCounts) {
    insert(simpleJdbcInsert(table), aggregatedAccessCounts, this::toMap);
  }

  protected Map<String, Object> toMap(AggregatedAccessCounts accessCounts) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put(AccessCountEventDao.FILE_ID_FIELD, accessCounts.getFileId());
    parameters.put(AccessCountEventDao.ACCESS_COUNT_FIELD, accessCounts.getAccessCount());
    parameters.put(AccessCountEventDao.LAST_ACCESSED_TIME_FIELD,
        accessCounts.getLastAccessedTimestamp());
    return parameters;
  }

  @Override
  public void validate(AccessCountTable table) throws MetaStoreException {
    MetastoreQuery query = select(FILE_ID_FIELD, ACCESS_COUNT_FIELD, LAST_ACCESSED_TIME_FIELD)
        .from(table.getTableName())
        .limit(1);
    try {
      queryExecutor.execute(query, new ColumnMapRowMapper());
    } catch (Exception exception) {
      throw new MetaStoreException(exception);
    }
  }

  @Override
  public void updateFileIds(List<AccessCountTable> accessCountTables,
                            long srcFileId, long destFileId) throws MetaStoreException {
    Exception lastException = null;
    int failedNum = 0;

    for (AccessCountTable table : accessCountTables) {
      String statement = "UPDATE " + table.getTableName()
          + " SET fid = " + destFileId
          + " WHERE fid = " + srcFileId;

      try {
        jdbcTemplate.execute(statement);
      } catch (Exception exception) {
        lastException = exception;
        failedNum++;
      }
    }
    // Otherwise, ignore the exception because table evictor can evict access
    // count tables, which are not synchronized. Even so, there is no impact on
    // the measurement for data temperature.
    if (failedNum == accessCountTables.size()) {
      // Throw exception if all tables are not updated.
      throw new MetaStoreException("Failed to update fid!", lastException);
    }
  }

  private SimpleJdbcInsert simpleJdbcInsert(AccessCountTable table) {
    return new SimpleJdbcInsert(dataSource)
        .withTableName(table.getTableName());
  }

  @Override
  protected MetastoreQuery searchQuery(FileAccessInfoSearchRequest searchRequest) {
    return select("access_counts.fid AS fid",
        "SUM(access_counts.count) AS count",
        "MAX(access_counts.last_accessed_time) as last_accessed_time",
        "file.path as path")
        .fromSubQuery(AccessCountEventDao.unionTablesQuery(searchRequest.getAccessCountTables()),
            "access_counts")
        .join("file", ImmutableMap.of("access_counts.fid", "file.fid"))
        .where(
            in("access_counts.fid", searchRequest.getIds()),
            like("file.path", searchRequest.getPathLike()),
            betweenEpochInclusive("access_counts.last_accessed_time",
                searchRequest.getLastAccessedTime())
        )
        .groupBy("access_counts.fid", "file.path");
  }

  @Override
  protected FileAccessInfo mapRow(ResultSet rs, int rowNum) throws SQLException {
    return FileAccessInfo.builder()
        .setFid(rs.getLong(AccessCountEventDao.FILE_ID_FIELD))
        .setPath(rs.getString(FileInfoDao.FILE_PATH_FIELD))
        .setAccessCount(rs.getInt(AccessCountEventDao.ACCESS_COUNT_FIELD))
        .setLastAccessedTime(rs.getLong(AccessCountEventDao.LAST_ACCESSED_TIME_FIELD))
        .build();
  }
}
