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

import org.junit.Test;
import org.smartdata.metastore.dao.FileAccessPartitionDao;
import org.smartdata.metastore.model.FileAccessPartition;
import org.smartdata.metastore.partition.cleanup.FileAccessPartitionRetentionPolicyExecutor;

import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class MonthCountFileAccessPartitionRetentionPolicyExecutorTest {

  private FileAccessPartitionRetentionPolicyExecutor retentionPolicyExecutor;
  private final FileAccessPartitionDao mockFileAccessPartitionDao =
      mock(FileAccessPartitionDao.class);

  @Test
  public void cleanupRedundantPartitions() {
    int retentionCount = 2;
    retentionPolicyExecutor =
        new MonthCountFileAccessPartitionRetentionPolicyExecutor(mockFileAccessPartitionDao,
            retentionCount);
    List<FileAccessPartition> partitions = Arrays.asList(
        new FileAccessPartition(1, "2024-07-01",
            LocalDate.of(2024, 7, 1)),
        new FileAccessPartition(2, "2024-08-01",
            LocalDate.of(2024, 8, 1)),
        new FileAccessPartition(3, "2024-09-01",
            LocalDate.of(2024, 9, 1)),
        new FileAccessPartition(4, "2024-10-01",
            LocalDate.of(2024, 10, 1)),
        new FileAccessPartition(5, "2024-11-01",
            LocalDate.of(2024, 11, 1))
    );
    when(mockFileAccessPartitionDao.getAll()).thenReturn(partitions);
    retentionPolicyExecutor.cleanup();
    verify(mockFileAccessPartitionDao, times(1)).remove(eq(partitions.get(3)));
    verify(mockFileAccessPartitionDao, times(1)).remove(eq(partitions.get(4)));
  }

  @Test
  public void testCleanupWithoutRedundantPartitions() {
    int retentionCount = 2;
    retentionPolicyExecutor =
        new MonthCountFileAccessPartitionRetentionPolicyExecutor(mockFileAccessPartitionDao,
            retentionCount);
    List<FileAccessPartition> partitions = Arrays.asList(
        new FileAccessPartition(1, "2024-07-01",
            LocalDate.of(2024, 7, 1)),
        new FileAccessPartition(2, "2024-08-01",
            LocalDate.of(2024, 8, 1)),
        new FileAccessPartition(3, "2024-09-01",
            LocalDate.of(2024, 9, 1))
    );
    when(mockFileAccessPartitionDao.getAll()).thenReturn(partitions);
    retentionPolicyExecutor.cleanup();
    verify(mockFileAccessPartitionDao, never()).remove(any());
  }

  @Test
  public void testCleanupWithIncorrectRetentionCount() {
    int retentionCount = -1;
    retentionPolicyExecutor =
        new MonthCountFileAccessPartitionRetentionPolicyExecutor(mockFileAccessPartitionDao,
            retentionCount);
    List<FileAccessPartition> partitions = Arrays.asList(
        new FileAccessPartition(1, "2024-07-01",
            LocalDate.of(2024, 7, 1)),
        new FileAccessPartition(2, "2024-08-01",
            LocalDate.of(2024, 8, 1)),
        new FileAccessPartition(3, "2024-09-01",
            LocalDate.of(2024, 9, 1))
    );
    retentionPolicyExecutor.cleanup();
    verify(mockFileAccessPartitionDao, never()).getAll();
    verify(mockFileAccessPartitionDao, never()).remove(any());
  }
}
