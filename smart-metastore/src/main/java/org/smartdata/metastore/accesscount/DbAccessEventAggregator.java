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
import org.smartdata.metastore.accesscount.failover.AccessCountContext;
import org.smartdata.metastore.accesscount.failover.Failover;
import org.smartdata.metastore.dao.FileInfoDao;
import org.smartdata.metastore.model.AggregatedAccessCounts;
import org.smartdata.metrics.FileAccessEvent;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Slf4j
public class DbAccessEventAggregator implements AccessEventAggregator {

  private final FileInfoDao fileInfoDao;
  private final FileAccessManager dbTableManager;
  private final Failover<AccessCountContext> accessCountFailover;

  public DbAccessEventAggregator(FileInfoDao fileInfoDao,
                                 FileAccessManager dbTableManager,
                                 Failover<AccessCountContext> failover) {
    this.fileInfoDao = fileInfoDao;
    this.dbTableManager = dbTableManager;
    this.accessCountFailover = failover;
  }

  @Override
  public void aggregate(List<FileAccessEvent> events) {
    List<AggregatedAccessCounts> fileAccessCounts = getAggregatedAccessCounts(events);
    AccessCountContext accessCountContext =
        new AccessCountContext(fileAccessCounts);
    accessCountFailover.execute(ctx -> dbTableManager.save(accessCountContext.getAccessCounts()),
        accessCountContext);
  }

  private List<AggregatedAccessCounts> getAggregatedAccessCounts(List<FileAccessEvent> events) {
    List<String> paths =
        events.stream()
            .map(FileAccessEvent::getPath)
            .collect(Collectors.toList());
    final Map<String, Long> pathFids = getFileIdMap(paths);
    return events.stream()
        .map(e -> {
          Long fileId = pathFids.get(e.getPath());
          if (fileId != null) {
            return AggregatedAccessCounts.fromEvent(e).withFileId(fileId);
          } else {
            return null;
          }
        })
        .filter(Objects::nonNull)
        .collect(Collectors.toList());
  }

  private Map<String, Long> getFileIdMap(List<String> paths) {
    try {
      return fileInfoDao.getPathFids(paths);
    } catch (Exception e) {
      log.error("Error fetching file ids for paths {}", paths, e);
      return Collections.emptyMap();
    }
  }
}
