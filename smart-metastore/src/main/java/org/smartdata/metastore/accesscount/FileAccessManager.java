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
import org.smartdata.metastore.dao.Searchable;
import org.smartdata.metastore.model.AggregatedAccessCounts;
import org.smartdata.metastore.model.SearchResult;
import org.smartdata.metastore.queries.PageRequest;
import org.smartdata.metastore.queries.sort.FileAccessInfoSortField;
import org.smartdata.metastore.transaction.TransactionRunner;
import org.smartdata.model.FileAccessInfo;
import org.smartdata.model.request.FileAccessInfoSearchRequest;

import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.LongSummaryStatistics;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.collectingAndThen;

@Slf4j
public class FileAccessManager implements
    Searchable<FileAccessInfoSearchRequest, FileAccessInfo, FileAccessInfoSortField> {

  private final TransactionRunner transactionRunner;
  private final FileAccessDao fileAccessDao;
  private final CacheFileDao cacheFileDao;

  public FileAccessManager(
      TransactionRunner transactionRunner,
      FileAccessDao fileAccessDao,
      CacheFileDao cacheFileDao) {
    this.fileAccessDao = fileAccessDao;
    this.cacheFileDao = cacheFileDao;
    this.transactionRunner = transactionRunner;
  }

  @Override
  public SearchResult<FileAccessInfo> search(FileAccessInfoSearchRequest searchRequest,
                                             PageRequest<FileAccessInfoSortField> pageRequest) {
    return fileAccessDao.search(searchRequest, pageRequest);
  }

  @Override
  public List<FileAccessInfo> search(FileAccessInfoSearchRequest searchRequest) {
    return fileAccessDao.search(searchRequest);
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
    Map<Long, AggregatedAccessCounts> aggregatedAccessCounts = accessCounts.stream()
        .collect(Collectors.groupingBy(AggregatedAccessCounts::getFileId,
            collectingAndThen(Collectors.toList(), list -> {
              AggregatedAccessCounts maxAccessTime = list.stream()
                  .max(Comparator.comparingLong(AggregatedAccessCounts::getAccessTimestamp))
                  .orElse(null);
              LongSummaryStatistics accessCount = list.stream()
                  .collect(Collectors.summarizingLong(AggregatedAccessCounts::getAccessCount));
              return Optional.ofNullable(maxAccessTime)
                  .map(maxAggAccessCount ->
                      new AggregatedAccessCounts(maxAggAccessCount.getFileId(),
                          accessCount.getSum(),
                          maxAggAccessCount.getAccessTimestamp()))
                  .orElse(null);
            })));
    return aggregatedAccessCounts.values().stream()
        .filter(Objects::nonNull)
        .collect(Collectors.toList());
  }
}
