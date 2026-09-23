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

import org.smartdata.hive.catalog.HiveCatalogDao;
import org.smartdata.hive.catalog.HiveDatabaseInfo;
import org.smartdata.hive.catalog.HivePartitionInfo;
import org.smartdata.hive.catalog.HiveTableInfo;
import org.smartdata.metastore.dao.HiveDatabaseDao;
import org.smartdata.metastore.dao.HivePartitionDao;
import org.smartdata.metastore.dao.HiveTableDao;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

public class PostgresHiveCatalogDao implements HiveCatalogDao {
  private final HiveDatabaseDao databaseDao;
  private final HiveTableDao tableDao;
  private final HivePartitionDao partitionDao;
  private final TransactionTemplate transactionTemplate;

  public PostgresHiveCatalogDao(
      HiveDatabaseDao databaseDao,
      HiveTableDao tableDao,
      HivePartitionDao partitionDao,
      PlatformTransactionManager transactionManager) {
    this.databaseDao = databaseDao;
    this.tableDao = tableDao;
    this.partitionDao = partitionDao;
    this.transactionTemplate = new TransactionTemplate(transactionManager);
    this.transactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_NESTED);
  }

  @Override
  public void upsertDatabase(HiveDatabaseInfo database) {
    databaseDao.upsert(database);
  }

  @Override
  public void deleteDatabase(String dbName) {
    executeWithoutResult(status -> {
      partitionDao.deleteByDbName(dbName);
      tableDao.deleteByDbName(dbName);
      databaseDao.delete(dbName);
    });
  }

  @Override
  public void upsertTable(HiveTableInfo table) {
    tableDao.upsert(table);
  }

  @Override
  public void alterTable(HiveTableInfo tableBefore, HiveTableInfo tableAfter) {
    executeWithoutResult(status -> {
      boolean isRenamed = !tableBefore.getFullName().equals(tableAfter.getFullName());
      if (isRenamed) {
        partitionDao.renameTable(
            tableBefore.getDbName(), tableBefore.getName(),
            tableAfter.getDbName(), tableAfter.getName());
        tableDao.delete(tableBefore.getDbName(), tableBefore.getName());

        // this block should be executed only when table is renamed since Hive
        // does not update the location of old partitions after SET LOCATION for table
        if (!Objects.equals(tableBefore.getLocation(), tableAfter.getLocation())) {
          partitionDao.replaceLocation(
              tableAfter.getDbName(), tableAfter.getName(),
              tableBefore.getLocation(), tableAfter.getLocation());
        }
      }
      tableDao.upsert(tableAfter);
    });
  }

  @Override
  public void deleteTable(String dbName, String tableName) {
    executeWithoutResult(status -> {
      partitionDao.deleteByTable(dbName, tableName);
      tableDao.delete(dbName, tableName);
    });
  }

  @Override
  public void upsertPartitions(Collection<HivePartitionInfo> partitions) {
    partitionDao.upsert(partitions);
  }

  @Override
  public void deletePartitions(String dbName, String tableName, Collection<String> partitionNames) {
    partitionDao.delete(dbName, tableName, partitionNames);
  }

  @Override
  public void alterPartition(HivePartitionInfo partitionBefore, HivePartitionInfo partitionAfter) {
    executeWithoutResult(status -> {
      if (!partitionBefore.getFullName().equals(partitionAfter.getFullName())) {
        partitionDao.delete(
            partitionBefore.getDbName(),
            partitionBefore.getTableName(),
            Collections.singletonList(partitionBefore.getName()));
      }
      partitionDao.upsert(Collections.singletonList(partitionAfter));
    });
  }

  @Override
  public void deleteAll() {
    executeWithoutResult(status -> {
      partitionDao.deleteAll();
      tableDao.deleteAll();
      databaseDao.deleteAll();
    });
  }

  @Override
  public <T> T execute(TransactionCallback<T> action) throws TransactionException {
    return transactionTemplate.execute(action);
  }
}
