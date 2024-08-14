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

import org.smartdata.exception.NotFoundException;
import org.smartdata.metastore.model.AggregatedAccessCounts;
import org.smartdata.metastore.queries.sort.CachedFilesSortField;
import org.smartdata.model.CachedFileStatus;
import org.smartdata.model.request.CachedFileSearchRequest;

import java.util.Collection;
import java.util.List;

public interface CacheFileDao
    extends Searchable<CachedFileSearchRequest, CachedFileStatus, CachedFilesSortField> {
  List<CachedFileStatus> getAll();

  CachedFileStatus getById(long fid) throws NotFoundException;

  List<Long> getFids();

  void insert(CachedFileStatus cachedFileStatus);

  void insert(long fid, String path, long fromTime,
              long lastAccessTime, int numAccessed);

  void insert(List<CachedFileStatus> cachedFileStatusList);

  int update(Long fid, Long lastAccessTime, long numAccessed);

  void update(Collection<AggregatedAccessCounts> events);

  void deleteById(long fid);

  void deleteAll();
}
