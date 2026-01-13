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

import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.smartdata.metastore.dao.AbstractDao;
import org.smartdata.metrics.GeneralFileInfoSource;
import org.smartdata.model.BaseFileInfo;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public abstract class BaseFileInfoDao extends AbstractDao implements GeneralFileInfoSource {

  protected final NamedParameterJdbcTemplate namedParameterJdbcTemplate;

  public BaseFileInfoDao(DataSource dataSource, String tableName) {
    super(dataSource, tableName);
    this.namedParameterJdbcTemplate = new NamedParameterJdbcTemplate(dataSource);
  }

  @Override
  public Map<String, Long> getPathsToIdsMapping(Collection<String> paths) {
    List<GeneralFileInfo> files = namedParameterJdbcTemplate.query(
        "SELECT * FROM "
            + tableName
            + " WHERE path IN (:paths)",
        new MapSqlParameterSource("paths", paths),
        this::mapRow);
    return files.stream()
        .collect(Collectors.toMap(
            GeneralFileInfo::getPath,
            GeneralFileInfo::getId));
  }

  @Override
  public List<String> getFilePathsByPrefix(String path) {
    return jdbcTemplate.query(
        "SELECT * FROM "
            + tableName
            + " WHERE path LIKE ?",
        this::extractPath, path + "%");
  }

  @Override
  public BaseFileInfo getBaseFileInfo(String path) {
    return jdbcTemplate.queryForObject("SELECT * FROM file WHERE path = ?",
        this::toBaseFileInfo, path);
  }

  private GeneralFileInfo mapRow(ResultSet resultSet, int i) throws SQLException {
    return new GeneralFileInfo(
        resultSet.getLong("fid"),
        resultSet.getString("path")
    );
  }

  private String extractPath(ResultSet resultSet, int i) throws SQLException {
    return resultSet.getString("path");
  }

  private BaseFileInfo toBaseFileInfo(ResultSet resultSet, int i) throws SQLException {
    return new BaseFileInfoImpl(
        resultSet.getString("path"),
        resultSet.getLong("length"),
        resultSet.getBoolean("is_dir")
    );
  }

  @Data
  private static class GeneralFileInfo {
    private final long id;
    private final String path;
  }

  @RequiredArgsConstructor
  @Data
  private static class BaseFileInfoImpl implements BaseFileInfo {
    private final String path;
    private final long length;
    private final boolean isDir;
  }
}
