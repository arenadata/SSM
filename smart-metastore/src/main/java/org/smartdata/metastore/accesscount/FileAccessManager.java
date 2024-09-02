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
package org.smartdata.metastore.accesscount;

import lombok.extern.slf4j.Slf4j;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.dao.CacheFileDao;
import org.smartdata.metastore.dao.FileAccessDao;
import org.smartdata.metastore.dao.SearchableService;
import org.smartdata.metastore.model.AggregatedAccessCounts;
import org.smartdata.metastore.queries.sort.FileAccessInfoSortField;
import org.smartdata.metastore.transaction.TransactionRunner;
import org.smartdata.model.FileAccessInfo;
import org.smartdata.model.request.FileAccessInfoSearchRequest;

import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
public class FileAccessManager extends
    SearchableService<FileAccessInfoSearchRequest, FileAccessInfo, FileAccessInfoSortField> {

  private final TransactionRunner transactionRunner;
  private final FileAccessDao fileAccessDao;
  private final CacheFileDao cacheFileDao;

  public FileAccessManager(
      TransactionRunner transactionRunner,
      FileAccessDao fileAccessDao,
      CacheFileDao cacheFileDao) {
    super(fileAccessDao, "file accesses");
    this.fileAccessDao = fileAccessDao;
    this.cacheFileDao = cacheFileDao;
    this.transactionRunner = transactionRunner;
  }

  public void save(Collection<AggregatedAccessCounts> accessCounts) {
    if (accessCounts.isEmpty()) {
      return;
    }
    try {
      transactionRunner.inTransaction(() -> {
        insertFileAccesses(accessCounts);
        updateCachedFilesInMetastore(getAggregatedAccessCounts(accessCounts));
      });
    } catch (MetaStoreException e) {
      log.error("Failed to save access counts", e);
      throw new RuntimeException(e);
    }
  }

  private void insertFileAccesses(
      Collection<AggregatedAccessCounts> accessCounts) throws MetaStoreException {
    try {
      fileAccessDao.insert(accessCounts);
      log.debug("Inserted values {} to file access table", accessCounts);
    } catch (Exception e) {
      log.error("Error inserting file accesses {}", accessCounts, e);
      throw new MetaStoreException(e);
    }
  }

  private void updateCachedFilesInMetastore(Collection<AggregatedAccessCounts> accessCounts)
      throws MetaStoreException {
    try {
      cacheFileDao.update(accessCounts);
    } catch (Exception e) {
      log.error("Error updating cached files {}", accessCounts, e);
      throw new MetaStoreException(e);
    }
  }

  private Collection<AggregatedAccessCounts> getAggregatedAccessCounts(
      Collection<AggregatedAccessCounts> accessCounts) {
    Map<Long, AggregatedAccessCounts> aggregatedAccessCounts =
        accessCounts.stream()
            .collect(Collectors.toMap(
                AggregatedAccessCounts::getFileId,
                Function.identity(),
                AggregatedAccessCounts::merge
            ));
    return aggregatedAccessCounts.values().stream()
        .filter(Objects::nonNull)
        .collect(Collectors.toList());
  }
}
