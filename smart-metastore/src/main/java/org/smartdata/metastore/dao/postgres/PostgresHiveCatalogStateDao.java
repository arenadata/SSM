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
package org.smartdata.metastore.dao.postgres;

import org.smartdata.hive.catalog.HiveCatalogStateDao;
import org.smartdata.metastore.dao.SystemInfoDao;
import org.smartdata.model.SystemInfo;

/**
 * Stores the Hive catalog state in the system info table,
 * so that no separate table is required for a single flag.
 */
public class PostgresHiveCatalogStateDao implements HiveCatalogStateDao {
  static final String INITIALIZED_PROPERTY = "hive.catalog.initialized";

  private final SystemInfoDao systemInfoDao;

  public PostgresHiveCatalogStateDao(SystemInfoDao systemInfoDao) {
    this.systemInfoDao = systemInfoDao;
  }

  @Override
  public boolean isInitialized() {
    return systemInfoDao.containsProperty(INITIALIZED_PROPERTY);
  }

  @Override
  public void markInitialized() {
    if (!isInitialized()) {
      systemInfoDao.insert(new SystemInfo(INITIALIZED_PROPERTY, Boolean.TRUE.toString()));
    }
  }
}
