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
package org.smartdata.metastore.partition;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.smartdata.metastore.partition.cleanup.FileAccessPartitionRetentionPolicyExecutor;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

@RequiredArgsConstructor
@Slf4j
public class FileAccessPartitionService {
  private static final int CREATE_PARTITION_INTERVAL_DAYS = 30;
  private static final int CLEANUP_PARTITION_INTERVAL_DAYS = 30;
  private final ScheduledExecutorService scheduledExecutorService;
  private final CreatePartitionTask createPartitionTask;
  private final CleanupPartitionTask cleanupPartitionTask;
  private ScheduledFuture<?> createPartitionFuture;
  private ScheduledFuture<?> removePartitionFuture;

  public FileAccessPartitionService(ScheduledExecutorService service,
                                    FileAccessPartitionManager fileAccessPartitionManager,
                                    FileAccessPartitionRetentionPolicyExecutor retentionPolicyExecutor) {
    this.scheduledExecutorService = service;
    this.createPartitionTask = new CreatePartitionTask(fileAccessPartitionManager);
    this.cleanupPartitionTask = new CleanupPartitionTask(retentionPolicyExecutor);
  }

  public void start() {
    this.createPartitionFuture = scheduledExecutorService.scheduleAtFixedRate(
        createPartitionTask, 0, CREATE_PARTITION_INTERVAL_DAYS, TimeUnit.DAYS);
    this.removePartitionFuture = scheduledExecutorService.scheduleAtFixedRate(
        cleanupPartitionTask, 0, CLEANUP_PARTITION_INTERVAL_DAYS, TimeUnit.DAYS);
  }

  public void stop() {
    if (createPartitionFuture != null) {
      createPartitionFuture.cancel(true);
    }
    if (removePartitionFuture != null) {
      removePartitionFuture.cancel(true);
    }
  }

  @RequiredArgsConstructor
  private static class CreatePartitionTask implements Runnable {
    private final FileAccessPartitionManager partitionManager;

    @Override
    public void run() {
      try {
        partitionManager.createNewPartitions();
      } catch (Exception e) {
        log.error("CreatePartitionTask failed", e);
      }
    }
  }

  @RequiredArgsConstructor
  private static class CleanupPartitionTask implements Runnable {
    private final FileAccessPartitionRetentionPolicyExecutor retentionPolicyExecutor;

    @Override
    public void run() {
      try {
        retentionPolicyExecutor.cleanup();
      } catch (Exception e) {
        log.error("CleanupPartitionTask failed", e);
      }
    }
  }
}
