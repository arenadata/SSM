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
package org.smartdata.metastore.partition;

import lombok.extern.slf4j.Slf4j;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.dao.FileAccessPartitionDao;

import java.time.LocalDateTime;

@Slf4j
public class FileAccessPartitionManagerImpl implements FileAccessPartitionManager {

  private final FileAccessPartitionDao fileAccessPartitionDao;

  public FileAccessPartitionManagerImpl(MetaStore metaStore) {
    this.fileAccessPartitionDao = metaStore.fileAccessPartitionDao();
  }

  @Override
  public void createNewPartitions() {
    try {
      //create partition for current and next months if they don't exist
      LocalDateTime currentDate = LocalDateTime.now();
      fileAccessPartitionDao.create(currentDate);
      fileAccessPartitionDao.create(currentDate.plusMonths(1));
    } catch (MetaStoreException e) {
      log.error("Failed to create partitions", e);
      throw new RuntimeException(e);
    }
  }
}
