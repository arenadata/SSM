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
package org.smartdata.metastore.partition.cleanup;

import lombok.RequiredArgsConstructor;
import org.smartdata.conf.SmartConf;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.partition.cleanup.impl.MonthCountFileAccessPartitionRetentionPolicyExecutor;

import static org.smartdata.conf.SmartConfKeys.SMART_FILE_ACCESS_PARTITIONS_RETENTION_COUNT_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_FILE_ACCESS_PARTITIONS_RETENTION_COUNT_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_FILE_ACCESS_PARTITIONS_RETENTION_POLICY_KEY;

@RequiredArgsConstructor
public class FileAccessPartitionRetentionPolicyExecutorFactory {

  private final MetaStore metaStore;

  public FileAccessPartitionRetentionPolicyExecutor createPolicyExecutor(SmartConf conf) {
    FileAccessPartitionRetentionPolicyType policyType =
        conf.getEnum(SMART_FILE_ACCESS_PARTITIONS_RETENTION_POLICY_KEY,
            FileAccessPartitionRetentionPolicyType.MONTH_COUNT);
    int retentionCount = conf.getInt(SMART_FILE_ACCESS_PARTITIONS_RETENTION_COUNT_KEY,
        SMART_FILE_ACCESS_PARTITIONS_RETENTION_COUNT_DEFAULT);
    switch (policyType) {
      case MONTH_COUNT:
      default:
        return new MonthCountFileAccessPartitionRetentionPolicyExecutor(
            metaStore.fileAccessPartitionDao(),
            retentionCount);
    }
  }
}


















