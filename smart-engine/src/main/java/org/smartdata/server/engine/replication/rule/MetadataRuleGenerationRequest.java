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
package org.smartdata.server.engine.replication.rule;

import lombok.Builder;
import lombok.Value;
import org.smartdata.model.ClusterInfo;
import org.smartdata.model.replication.MetadataReplicationSettings;
import org.smartdata.model.replication.ReplicationSchedule;
import org.smartdata.model.replication.ReplicationSource;

@Value
@Builder
public class MetadataRuleGenerationRequest {
  ReplicationSource source;
  MetadataReplicationSettings settings;
  ReplicationSchedule schedule;
  ClusterInfo targetCluster;
  /** Nameservice of the source HDFS, which is renamed in the replicated metadata. */
  String sourceNameservice;
}
