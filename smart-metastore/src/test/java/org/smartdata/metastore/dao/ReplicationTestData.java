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

import org.smartdata.model.ClusterInfo;
import org.smartdata.model.ClusterStatus;
import org.smartdata.model.FileDiffType;
import org.smartdata.model.HiveOperation;
import org.smartdata.model.PreserveAttribute;
import org.smartdata.model.replication.DataReplicationSettings;
import org.smartdata.model.replication.MetadataReplicationSettings;
import org.smartdata.model.replication.ReplicationPolicyInfo;
import org.smartdata.model.replication.ReplicationPolicyStatus;
import org.smartdata.model.replication.ReplicationSchedule;
import org.smartdata.model.replication.ReplicationSource;

import java.time.Instant;
import java.util.Collections;
import java.util.EnumSet;

public class ReplicationTestData {
  public static final Instant CREATE_TIME = Instant.ofEpochMilli(1000L);

  public static ClusterInfo.Builder cluster(String name) {
    return ClusterInfo.builder()
        .name(name)
        .status(ClusterStatus.ACTIVE)
        .hdfsUri("hdfs://" + name)
        .hiveThriftUri("thrift://" + name + ":9083")
        .hdfsNameservice(name)
        .createTime(CREATE_TIME)
        .updateTime(CREATE_TIME);
  }

  /**
   * Builds policy replicating the whole database with the default settings.
   */
  public static ReplicationPolicyInfo.Builder policy(String name, long clusterId, String dbName) {
    return ReplicationPolicyInfo.builder()
        .name(name)
        .status(ReplicationPolicyStatus.CREATED)
        .tags(Collections.emptyList())
        .source(ReplicationSource.builder()
            .databases(Collections.singletonList(dbName))
            .tables(Collections.emptyList())
            .build())
        .targetClusterId(clusterId)
        .dataReplication(DataReplicationSettings.builder()
            .enabled(true)
            .preservedAttributes(EnumSet.of(
                PreserveAttribute.OWNER, PreserveAttribute.GROUP, PreserveAttribute.PERMISSIONS))
            .events(EnumSet.copyOf(FileDiffType.FILTERABLE_DIFF_TYPES))
            .build())
        .metadataReplication(MetadataReplicationSettings.builder()
            .enabled(true)
            .events(EnumSet.copyOf(HiveOperation.FILTERABLE_OPERATIONS))
            .build())
        .schedule(ReplicationSchedule.eventDriven())
        .createTime(CREATE_TIME)
        .updateTime(CREATE_TIME);
  }
}
