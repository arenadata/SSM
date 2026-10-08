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
package org.smartdata.model;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

/**
 * Target cluster of the replication policies.
 */
@Data
@Builder(toBuilder = true)
public class ClusterInfo {
  private final Long id;
  private final String name;
  private final ClusterStatus status;
  private final String hdfsUri;
  private final String hiveThriftUri;
  /** Nameservice of the target HDFS, which replaces the source one in the replicated metadata. */
  private final String hdfsNameservice;
  private final Instant createTime;
  private final Instant updateTime;
}
