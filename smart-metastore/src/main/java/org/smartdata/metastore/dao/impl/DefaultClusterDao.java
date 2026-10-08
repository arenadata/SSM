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

import org.smartdata.metastore.SearchableAbstractDao;
import org.smartdata.metastore.dao.ClusterDao;
import org.smartdata.metastore.queries.MetastoreQuery;
import org.smartdata.metastore.queries.sort.ClusterSortField;
import org.smartdata.model.ClusterInfo;
import org.smartdata.model.ClusterStatus;
import org.smartdata.model.request.ClusterSearchRequest;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.smartdata.metastore.queries.MetastoreQuery.selectAll;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.equal;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.inStrings;
import static org.smartdata.metastore.queries.expression.MetastoreQueryDsl.likeCaseInsensitive;

public class DefaultClusterDao
    extends SearchableAbstractDao<ClusterSearchRequest, ClusterInfo, ClusterSortField>
    implements ClusterDao {

  private static final String TABLE_NAME = "cluster";

  private static final String ID_FIELD = "id";
  private static final String NAME_FIELD = "name";
  private static final String STATUS_FIELD = "status";
  private static final String HDFS_URI_FIELD = "hdfs_uri";
  private static final String HIVE_THRIFT_URI_FIELD = "hive_thrift_uri";
  private static final String HDFS_NAMESERVICE_FIELD = "hdfs_nameservice";
  private static final String CREATE_TIME_FIELD = "create_time";
  private static final String UPDATE_TIME_FIELD = "update_time";

  public DefaultClusterDao(
      DataSource dataSource, PlatformTransactionManager transactionManager) {
    super(dataSource, transactionManager, TABLE_NAME);
  }

  @Override
  public Optional<ClusterInfo> getById(long id) {
    MetastoreQuery query = selectAll()
        .from(TABLE_NAME)
        .where(equal(ID_FIELD, id));
    return executeSingle(query);
  }

  @Override
  public long insert(ClusterInfo cluster) {
    return simpleJdbcInsert()
        .usingGeneratedKeyColumns(ID_FIELD)
        .executeAndReturnKey(toMap(cluster))
        .longValue();
  }

  @Override
  public boolean update(ClusterInfo cluster) {
    // AbstractDao#update skips null values, but the optional fields can be unset
    int updatedRows = jdbcTemplate.update("UPDATE " + TABLE_NAME + " SET "
            + NAME_FIELD + " = ?, "
            + STATUS_FIELD + " = ?, "
            + HDFS_URI_FIELD + " = ?, "
            + HIVE_THRIFT_URI_FIELD + " = ?, "
            + HDFS_NAMESERVICE_FIELD + " = ?, "
            + UPDATE_TIME_FIELD + " = ?"
            + " WHERE " + ID_FIELD + " = ?",
        cluster.getName(),
        cluster.getStatus().name(),
        cluster.getHdfsUri(),
        cluster.getHiveThriftUri(),
        cluster.getHdfsNameservice(),
        cluster.getUpdateTime().toEpochMilli(),
        cluster.getId());
    return updatedRows > 0;
  }

  @Override
  protected MetastoreQuery searchQuery(ClusterSearchRequest searchRequest) {
    return selectAll()
        .from(TABLE_NAME)
        .where(
            likeCaseInsensitive(NAME_FIELD, searchRequest.getNameLike()),
            inStrings(STATUS_FIELD, searchRequest.getStatuses())
        );
  }

  @Override
  protected ClusterInfo mapRow(ResultSet resultSet, int rowNum) throws SQLException {
    return ClusterInfo.builder()
        .id(resultSet.getLong(ID_FIELD))
        .name(resultSet.getString(NAME_FIELD))
        .status(ClusterStatus.valueOf(resultSet.getString(STATUS_FIELD)))
        .hdfsUri(resultSet.getString(HDFS_URI_FIELD))
        .hiveThriftUri(resultSet.getString(HIVE_THRIFT_URI_FIELD))
        .hdfsNameservice(resultSet.getString(HDFS_NAMESERVICE_FIELD))
        .createTime(Instant.ofEpochMilli(resultSet.getLong(CREATE_TIME_FIELD)))
        .updateTime(Instant.ofEpochMilli(resultSet.getLong(UPDATE_TIME_FIELD)))
        .build();
  }

  private Map<String, Object> toMap(ClusterInfo cluster) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put(NAME_FIELD, cluster.getName());
    parameters.put(STATUS_FIELD, cluster.getStatus().name());
    parameters.put(HDFS_URI_FIELD, cluster.getHdfsUri());
    parameters.put(HIVE_THRIFT_URI_FIELD, cluster.getHiveThriftUri());
    parameters.put(HDFS_NAMESERVICE_FIELD, cluster.getHdfsNameservice());
    parameters.put(CREATE_TIME_FIELD, cluster.getCreateTime().toEpochMilli());
    parameters.put(UPDATE_TIME_FIELD, cluster.getUpdateTime().toEpochMilli());
    return parameters;
  }
}
