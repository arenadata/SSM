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
package org.smartdata.metastore.dao;

import org.smartdata.model.FileInfo;
import org.smartdata.model.FileInfoUpdate;

import java.sql.SQLException;
import java.util.Collection;
import java.util.List;
import java.util.Map;

public interface FileInfoDao {

  List<FileInfo> getAll();

  List<FileInfo> getFilesByPrefix(String path);

  List<FileInfo> getFilesByPrefixInOrder(String path);

  List<FileInfo> getFilesByPaths(Collection<String> paths);

  FileInfo getById(long fid);

  FileInfo getByPath(String path);

  Map<String, Long> getPathFids(Collection<String> paths)
      throws SQLException;

  Map<Long, String> getFidPaths(Collection<Long> ids)
      throws SQLException;

  void insert(FileInfo fileInfo);

  void insert(FileInfo[] fileInfos);

  int update(String path, int storagePolicy);

  int updateByPath(String path, FileInfoUpdate fileUpdate);

  void deleteById(long fid);

  void deleteByPath(String path, boolean recursive);

  void deleteAll();

  void renameFile(String oldPath, String newPath, boolean recursive);
}
