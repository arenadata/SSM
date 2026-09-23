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

import org.smartdata.hive.catalog.HiveDatabaseInfo;
import org.smartdata.hive.catalog.HivePartitionInfo;
import org.smartdata.hive.catalog.HiveTableInfo;

public class HiveCatalogTestData {
  public static HiveDatabaseInfo.Builder database(String name) {
    return HiveDatabaseInfo.builder()
        .name(name)
        .location("hdfs://ns1/warehouse/" + name + ".db/");
  }

  public static HiveTableInfo.Builder table(String dbName, String name) {
    return HiveTableInfo.builder()
        .dbName(dbName)
        .name(name)
        .location("hdfs://ns1/warehouse/" + dbName + ".db/" + name + "/");
  }

  public static HivePartitionInfo.Builder partition(String dbName, String tableName, String name) {
    return HivePartitionInfo.builder()
        .dbName(dbName)
        .tableName(tableName)
        .name(name)
        .location("hdfs://ns1/warehouse/" + dbName + ".db/" + tableName + "/" + name + "/");
  }
}
