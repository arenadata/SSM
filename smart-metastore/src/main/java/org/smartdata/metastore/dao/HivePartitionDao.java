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

import org.smartdata.hive.catalog.HivePartitionInfo;

import java.util.Collection;
import java.util.List;

public interface HivePartitionDao {

  List<HivePartitionInfo> getByTable(String dbName, String tableName);

  void upsert(Collection<HivePartitionInfo> partitions);

  void delete(String dbName, String tableName, Collection<String> partitionNames);

  void deleteByTable(String dbName, String tableName);

  void deleteByDbName(String dbName);

  void deleteAll();

  void renameTable(String oldDbName, String oldTableName, String newDbName, String newTableName);

  void replaceLocation(String dbName, String tableName, String oldLocation, String newLocation);
}
