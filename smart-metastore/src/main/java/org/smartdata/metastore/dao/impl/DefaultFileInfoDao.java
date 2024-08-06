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

import org.smartdata.metastore.dao.AbstractDao;
import org.smartdata.metastore.dao.FileInfoDao;
import org.smartdata.model.FileInfo;
import org.smartdata.model.FileInfoDiff;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import javax.sql.DataSource;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DefaultFileInfoDao extends AbstractDao implements FileInfoDao {

  private static final String TABLE_NAME = "file";

  public DefaultFileInfoDao(DataSource dataSource) {
    super(dataSource, TABLE_NAME);
  }

  @Override
  public List<FileInfo> getAll() {
    return jdbcTemplate.query("SELECT * FROM file",
        new DefaultFileInfoDao.FileInfoRowMapper());
  }

  @Override
  public List<FileInfo> getFilesByPrefix(String path) {
    return jdbcTemplate.query("SELECT * FROM file WHERE path LIKE ?",
        new DefaultFileInfoDao.FileInfoRowMapper(), path + "%");
  }

  @Override
  public List<FileInfo> getFilesByPrefixInOrder(String path) {
    return jdbcTemplate.query("SELECT * FROM file WHERE path LIKE ? ORDER BY path ASC",
        new DefaultFileInfoDao.FileInfoRowMapper(), path + "%");
  }

  @Override
  public List<FileInfo> getFilesByPaths(Collection<String> paths) {
    NamedParameterJdbcTemplate namedParameterJdbcTemplate =
        new NamedParameterJdbcTemplate(dataSource);
    String sql = "SELECT * FROM file WHERE path IN (:paths)";
    MapSqlParameterSource parameterSource = new MapSqlParameterSource();
    parameterSource.addValue("paths", paths);
    return namedParameterJdbcTemplate.query(sql,
        parameterSource, new FileInfoRowMapper());
  }

  @Override
  public FileInfo getById(long fid) {
    return jdbcTemplate.queryForObject("SELECT * FROM file WHERE fid = ?",
        new Object[]{fid}, new DefaultFileInfoDao.FileInfoRowMapper());
  }

  @Override
  public FileInfo getByPath(String path) {
    return jdbcTemplate.queryForObject("SELECT * FROM file WHERE path = ?",
        new Object[]{path}, new DefaultFileInfoDao.FileInfoRowMapper());
  }

  @Override
  public Map<String, Long> getPathFids(Collection<String> paths)
      throws SQLException {
    NamedParameterJdbcTemplate namedParameterJdbcTemplate =
        new NamedParameterJdbcTemplate(dataSource);
    Map<String, Long> pathToId = new HashMap<>();
    String sql = "SELECT * FROM file WHERE path IN (:paths)";
    MapSqlParameterSource parameterSource = new MapSqlParameterSource();
    parameterSource.addValue("paths", paths);
    List<FileInfo> files = namedParameterJdbcTemplate.query(sql,
        parameterSource, new FileInfoRowMapper());
    for (FileInfo file : files) {
      pathToId.put(file.getPath(), file.getFileId());
    }
    return pathToId;
  }

  @Override
  public void insert(FileInfo fileInfo) {
    insert(fileInfo, this::toMap);
  }

  @Override
  public void insert(FileInfo[] fileInfos) {
    insert(fileInfos, this::toMap);
  }

  @Override
  public int update(String path, int storagePolicy) {
    final String sql = "UPDATE file SET sid =? WHERE path = ?;";
    return jdbcTemplate.update(sql, storagePolicy, path);
  }

  @Override
  public int updateByPath(String path, FileInfoDiff fileUpdate) {
    return update(updateToMap(fileUpdate), "path = ?", path);
  }

  @Override
  public void deleteById(long fid) {
    final String sql = "DELETE FROM file WHERE fid = ?";
    jdbcTemplate.update(sql, fid);
  }

  @Override
  public void deleteByPath(String path,  boolean recursive) {
    String sql = "DELETE FROM file WHERE path = ?";
    jdbcTemplate.update(sql, path);
    if (recursive) {
      sql = "DELETE FROM " + TABLE_NAME + " WHERE path LIKE ?";
      jdbcTemplate.update(sql, path + "/%");
    }
  }

  @Override
  public void deleteAll() {
    final String sql = "DELETE FROM file";
    jdbcTemplate.execute(sql);
  }

  @Override
  public void renameFile(String oldPath, String newPath, boolean recursive) {
    String sql = "UPDATE " + TABLE_NAME + " SET path = ? WHERE path = ?";
    jdbcTemplate.update(sql, newPath, oldPath);
    if (recursive) {
      renameDirectoryFiles(oldPath, newPath);
    }
  }

  protected void renameDirectoryFiles(String oldPath, String newPath) {
    String sql = "UPDATE " + TABLE_NAME
        + " SET path = CONCAT(?, SUBSTR(path, ?)) WHERE path LIKE ?";
    jdbcTemplate.update(sql, newPath, oldPath.length() + 1, oldPath + "/%");
  }

  private Map<String, Object> updateToMap(FileInfoDiff fileInfo) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put("path", fileInfo.getPath());
    parameters.put("length", fileInfo.getLength());
    parameters.put("block_replication", fileInfo.getBlockReplication());
    parameters.put("modification_time", fileInfo.getModificationTime());
    parameters.put("access_time", fileInfo.getAccessTime());
    parameters
        .put("owner", fileInfo.getOwner());
    parameters
        .put("owner_group", fileInfo.getGroup());
    parameters.put("permission", fileInfo.getPermission());
    parameters.put("ec_policy_id", fileInfo.getErasureCodingPolicy());
    return parameters;
  }

  private Map<String, Object> toMap(FileInfo fileInfo) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put("path", fileInfo.getPath());
    parameters.put("fid", fileInfo.getFileId());
    parameters.put("length", fileInfo.getLength());
    parameters.put("block_replication", fileInfo.getBlockReplication());
    parameters.put("block_size", fileInfo.getBlocksize());
    parameters.put("modification_time", fileInfo.getModificationTime());
    parameters.put("access_time", fileInfo.getAccessTime());
    parameters.put("is_dir", fileInfo.isdir());
    parameters.put("sid", fileInfo.getStoragePolicy());
    parameters
        .put("owner", fileInfo.getOwner());
    parameters
        .put("owner_group", fileInfo.getGroup());
    parameters.put("permission", fileInfo.getPermission());
    parameters.put("ec_policy_id", fileInfo.getErasureCodingPolicy());
    return parameters;
  }

  private static class FileInfoRowMapper implements RowMapper<FileInfo> {
    @Override
    public FileInfo mapRow(ResultSet resultSet, int i)
        throws SQLException {
      return new FileInfo(resultSet.getString("path"),
          resultSet.getLong("fid"),
          resultSet.getLong("length"),
          resultSet.getBoolean("is_dir"),
          resultSet.getShort("block_replication"),
          resultSet.getLong("block_size"),
          resultSet.getLong("modification_time"),
          resultSet.getLong("access_time"),
          resultSet.getShort("permission"),
          resultSet.getString("owner"),
          resultSet.getString("owner_group"),
          resultSet.getByte("sid"),
          resultSet.getByte("ec_policy_id")
      );
    }
  }
}
