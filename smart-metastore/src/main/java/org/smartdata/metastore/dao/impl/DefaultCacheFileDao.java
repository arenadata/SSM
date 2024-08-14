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

import org.smartdata.exception.NotFoundException;
import org.smartdata.metastore.SearchableAbstractDao;
import org.smartdata.metastore.dao.CacheFileDao;
import org.smartdata.metastore.model.AggregatedAccessCounts;
import org.smartdata.metastore.queries.MetastoreQuery;
import org.smartdata.metastore.queries.sort.CachedFilesSortField;
import org.smartdata.model.CachedFileStatus;
import org.smartdata.model.request.CachedFileSearchRequest;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.smartdata.metastore.queries.MetastoreQuery.selectAll;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.betweenEpochInclusive;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.equal;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.like;

public class DefaultCacheFileDao extends SearchableAbstractDao<
    CachedFileSearchRequest, CachedFileStatus, CachedFilesSortField>
    implements CacheFileDao {
  private static final String TABLE_NAME = "cached_file";

  public DefaultCacheFileDao(
      DataSource dataSource, PlatformTransactionManager transactionManager) {
    super(dataSource, transactionManager, TABLE_NAME);
  }

  @Override
  public List<CachedFileStatus> getAll() {
    MetastoreQuery query = selectAll().from(TABLE_NAME);
    return executeQuery(query);
  }

  @Override
  public CachedFileStatus getById(long fid) throws NotFoundException {
    MetastoreQuery query = selectAll()
        .from(TABLE_NAME)
        .where(
            equal("fid", fid)
        );
    return executeSingle(query)
        .orElseThrow(
            () -> new NotFoundException("Cached file status not found for id: " + fid));
  }

  @Override
  public List<Long> getFids() {
    String sql = "SELECT fid FROM cached_file";
    return jdbcTemplate.query(sql,
        (rs, rowNum) -> rs.getLong("fid"));
  }

  @Override
  public void insert(CachedFileStatus cachedFileStatus) {
    insert(cachedFileStatus, this::toMap);
  }

  @Override
  public void insert(long fid, String path, long fromTime,
                     long lastAccessTime, int numAccessed) {
    insert(new CachedFileStatus(fid, path,
        fromTime, lastAccessTime, numAccessed));
  }

  @Override
  public void insert(List<CachedFileStatus> cachedFileStatusList) {
    insert(cachedFileStatusList, this::toMap);
  }

  @Override
  public int update(Long fid, Long lastAccessTime, long numAccessed) {
    String sql = "UPDATE cached_file SET last_access_time = ?, accessed_num = ? WHERE fid = ?";
    return jdbcTemplate.update(sql, lastAccessTime, numAccessed, fid);
  }

  // todo use batch update
  @Override
  public void update(Collection<AggregatedAccessCounts> accessCounts) {
    Map<Long, CachedFileStatus> idToStatus = getAll().stream()
        .collect(Collectors.toMap(
            CachedFileStatus::getFid,
            Function.identity()
        ));

    for (AggregatedAccessCounts aggregatedAccessCounts : accessCounts) {
      Optional.of(aggregatedAccessCounts.getFileId())
          .map(idToStatus::get)
          .ifPresent(status -> merge(aggregatedAccessCounts, status));
    }
  }

  @Override
  public void deleteById(long fid) {
    final String sql = "DELETE FROM cached_file WHERE fid = ?";
    jdbcTemplate.update(sql, fid);
  }

  @Override
  public void deleteAll() {
    String sql = "DELETE FROM cached_file";
    jdbcTemplate.execute(sql);
  }

  private void merge(
      AggregatedAccessCounts aggregatedAccessCounts,
      CachedFileStatus cachedFileStatus) {
    long lastAccessTime = Math.max(
        cachedFileStatus.getLastAccessTime(),
        aggregatedAccessCounts.getLastAccessedTimestamp());
    long accessCounts = cachedFileStatus.getNumAccessed()
        + aggregatedAccessCounts.getAccessCount();

    update(aggregatedAccessCounts.getFileId(), lastAccessTime, accessCounts);
  }

  private Map<String, Object> toMap(CachedFileStatus cachedFileStatus) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put("fid", cachedFileStatus.getFid());
    parameters.put("path", cachedFileStatus.getPath());
    parameters.put("from_time", cachedFileStatus.getFromTime());
    parameters.put("last_access_time", cachedFileStatus.getLastAccessTime());
    parameters.put("accessed_num", cachedFileStatus.getNumAccessed());
    return parameters;
  }

  @Override
  protected MetastoreQuery searchQuery(CachedFileSearchRequest searchRequest) {
    return selectAll()
        .from(TABLE_NAME)
        .where(
            like("path", searchRequest.getPathLike()),
            betweenEpochInclusive("from_time", searchRequest.getCachedTime()),
            betweenEpochInclusive("last_access_time",
                searchRequest.getLastAccessedTime())
        );
  }

  @Override
  protected CachedFileStatus mapRow(ResultSet resultSet, int rowNum) throws SQLException {
    return CachedFileStatus.builder()
        .fid(resultSet.getLong("fid"))
        .path(resultSet.getString("path"))
        .fromTime(resultSet.getLong("from_time"))
        .lastAccessTime(resultSet.getLong("last_access_time"))
        .numAccessed(resultSet.getInt("accessed_num"))
        .build();
  }
}
