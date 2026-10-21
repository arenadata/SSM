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

import java.util.List;

/**
 * Source Hive entities of the replication policy. If neither tables,
 * nor table name pattern are specified, the whole databases are replicated.
 */
@Data
@Builder(toBuilder = true)
public class ReplicationSource {
  private final List<String> databases;
  /** Exact tables of the selected databases. */
  private final List<SourceTable> tables;
  /**
   * Glob pattern of the table names ({@code *} and {@code ?} wildcards),
   * applied to all the selected databases.
   */
  private final String tableNameRegex;
}
