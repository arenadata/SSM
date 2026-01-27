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
package org.smartdata.test.dao;

import org.smartdata.test.entity.HiveMetastoreEventEntity;

import java.util.List;
import java.util.Optional;

/**
 * DAO interface for accessing hive_metastore_event table.
 */
public interface HiveMetastoreEventDao {

  /**
   * Find a hive metastore event by ID.
   *
   * @param id the event ID
   * @return Optional containing the event if found, empty otherwise
   */
  Optional<HiveMetastoreEventEntity> findById(Long id);

  /**
   * Find all hive metastore events.
   *
   * @return list of all events
   */
  List<HiveMetastoreEventEntity> findAll();

  /**
   * Delete a hive metastore event by ID.
   *
   * @param id the event ID to delete
   * @return number of rows affected
   */
  int deleteById(Long id);
}
