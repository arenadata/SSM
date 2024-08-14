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
package org.smartdata.metastore.partition.cleanup.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.smartdata.metastore.dao.FileAccessPartitionDao;
import org.smartdata.metastore.model.FileAccessPartition;
import org.smartdata.metastore.partition.cleanup.FileAccessPartitionRetentionPolicyExecutor;
import org.smartdata.metastore.partition.cleanup.FileAccessPartitionRetentionPolicyType;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class MonthCountFileAccessPartitionRetentionPolicyExecutor
    implements FileAccessPartitionRetentionPolicyExecutor {

  private final FileAccessPartitionDao fileAccessPartitionDao;
  private final int monthCount;

  @Override
  public void cleanup() {
    if (monthCount <= 0) {
      return;
    }
    List<FileAccessPartition> fileAccessPartitions = fileAccessPartitionDao.getAll();
    //we should remove + 1 partition, because we also have partition for the next month
    if (fileAccessPartitions.size() > monthCount + 1) {
      List<FileAccessPartition> partitionsToRemove =
          fileAccessPartitions.subList(monthCount, fileAccessPartitions.size());
      for (FileAccessPartition fileAccessPartition : partitionsToRemove) {
        fileAccessPartitionDao.remove(fileAccessPartition);
      }
    }
    log.info(
        "File access partitions were cleanup successfully by retention policy: {},"
            + " retention count: {}",
        getPolicyType(), monthCount);
  }

  @Override
  public FileAccessPartitionRetentionPolicyType getPolicyType() {
    return FileAccessPartitionRetentionPolicyType.MONTH_COUNT;
  }
}
