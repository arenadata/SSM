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

import org.springframework.transaction.support.TransactionOperations;

import java.util.Collection;

/**
 * Write access to the SSM copy of the source Hive catalog.
 *
 * <p>Transactions started with {@link #execute} are nested ones if there is
 * an outer transaction, so that the failed catalog update can be retried
 * inside the outer transaction, e.g., the one used to store the HMS snapshot.
 */
public interface HiveCatalogDao extends TransactionOperations {
  String DATABASES_TABLE_NAME = "hive_database";
  String TABLES_TABLE_NAME = "hive_table";
  String PARTITIONS_TABLE_NAME = "hive_partition";

  void upsertDatabase(HiveDatabaseInfo database);

  void deleteDatabase(String dbName);

  void upsertTable(HiveTableInfo table);

  /**
   * Replaces the table state with the altered one, mirroring the HMS behavior:
   * <ul>
   *   <li>partitions of the renamed table are moved to the table with the new name;</li>
   *   <li>if the table was renamed along with its location change (HMS moves the data
   *   of tables with the default location on renaming), the location prefix of partitions,
   *   which are located inside the previous table location, is replaced with the new one;</li>
   *   <li>partitions aren't changed, if the table location was changed without renaming.</li>
   * </ul>
   */
  void alterTable(HiveTableInfo tableBefore, HiveTableInfo tableAfter);

  void deleteTable(String dbName, String tableName);

  void upsertPartitions(Collection<HivePartitionInfo> partitions);

  void deletePartitions(String dbName, String tableName, Collection<String> partitionNames);

  void alterPartition(HivePartitionInfo partitionBefore, HivePartitionInfo partitionAfter);

  void deleteAll();
}
