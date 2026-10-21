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

import org.smartdata.model.ClusterInfo;
import org.smartdata.model.replication.ReplicationSource;
import org.smartdata.model.replication.SourceTable;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;

final class RuleGenerationTestData {
  static final String SOURCE_NAMESERVICE = "ns1";

  private RuleGenerationTestData() {
  }

  static ClusterInfo.Builder targetCluster() {
    return ClusterInfo.builder()
        .name("backup")
        .hdfsUri("hdfs://ns2")
        .hiveThriftUri("thrift://backup:9083")
        .hdfsNameservice("ns2");
  }

  static ReplicationSource databases(String... dbNames) {
    return ReplicationSource.builder()
        .databases(List.of(dbNames))
        .build();
  }

  static ReplicationSource tables(List<String> dbNames, SourceTable... tables) {
    return ReplicationSource.builder()
        .databases(dbNames)
        .tables(List.of(tables))
        .build();
  }

  /** Time point in the server time zone, in which the rule time points are rendered. */
  static Instant timePoint(String dateTime) {
    return LocalDateTime.parse(dateTime.replace(' ', 'T'))
        .atZone(ZoneId.systemDefault())
        .toInstant();
  }
}
