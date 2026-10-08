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
package org.smartdata.model.replication;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.List;

/**
 * Replication of the source Hive databases data and/or metadata to the target cluster.
 */
@Data
@Builder(toBuilder = true)
public class ReplicationPolicyInfo {
  private final Long id;
  private final String name;
  private final String description;
  private final ReplicationPolicyStatus status;
  private final List<String> tags;
  private final ReplicationSource source;
  private final Long targetClusterId;
  private final DataReplicationSettings dataReplication;
  private final MetadataReplicationSettings metadataReplication;
  private final ReplicationSchedule schedule;
  private final Instant createTime;
  private final Instant updateTime;
}
