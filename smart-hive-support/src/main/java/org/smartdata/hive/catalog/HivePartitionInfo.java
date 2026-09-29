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
package org.smartdata.hive.catalog;

import lombok.Builder;
import lombok.Data;

import static org.smartdata.hive.fetch.HiveNotificationEvent.fullResourceName;

/**
 * State of the source Hive table partition as it is known to SSM
 * based on the handled HMS events.
 */
@Data
@Builder(toBuilder = true)
public class HivePartitionInfo {
  private final String dbName;
  private final String tableName;
  // partition name in the Hive format, e.g. "year=2026/month=09"
  private final String name;
  // can differ from the default partition location inside the table location
  private final String location;

  public String getFullName() {
    return fullResourceName(dbName, tableName, name);
  }
}
