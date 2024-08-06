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
package org.smartdata.server.engine;

import org.smartdata.metastore.dao.CacheFileDao;
import org.smartdata.metastore.dao.Searchable;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.CachedFilesSortField;
import org.smartdata.model.CachedFileStatus;
import org.smartdata.model.request.CachedFileSearchRequest;

import java.util.List;

public class CachedFilesManager implements
    Searchable<CachedFileSearchRequest, CachedFileStatus, CachedFilesSortField> {

  private final CacheFileDao cacheFileDao;

  public CachedFilesManager(CacheFileDao cacheFileDao) {
    this.cacheFileDao = cacheFileDao;
  }

  @Override
  public SearchResult<CachedFileStatus> search(
      CachedFileSearchRequest searchRequest, PageRequest<CachedFilesSortField> pageRequest) {
    return cacheFileDao.search(searchRequest, pageRequest);
  }

  @Override
  public List<CachedFileStatus> search(CachedFileSearchRequest searchRequest) {
    return cacheFileDao.search(searchRequest);
  }
}
