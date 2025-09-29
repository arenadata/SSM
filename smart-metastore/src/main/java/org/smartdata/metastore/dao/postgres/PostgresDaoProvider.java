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

import org.smartdata.hive.rule.HmsSyncProgressDao;
import org.smartdata.metastore.DBPool;
import org.smartdata.metastore.dao.ActionDao;
import org.smartdata.metastore.dao.CmdletDao;
import org.smartdata.metastore.dao.CompressionFileDao;
import org.smartdata.metastore.dao.FileStateDao;
import org.smartdata.metastore.dao.SmallFileDao;
import org.smartdata.metastore.dao.StorageDao;
import org.smartdata.metastore.dao.impl.DefaultDaoProvider;
import org.springframework.transaction.PlatformTransactionManager;

public class PostgresDaoProvider extends DefaultDaoProvider {
  public PostgresDaoProvider(DBPool dbPool, PlatformTransactionManager transactionManager) {
    super(dbPool, transactionManager);
  }

  @Override
  public StorageDao storageDao() {
    return new PostgresStorageDao(dataSource);
  }

  @Override
  public FileStateDao fileStateDao() {
    return new PostgresFileStateDao(dataSource);
  }

  @Override
  public CompressionFileDao compressionFileDao() {
    return new PostgresCompressionFileDao(dataSource);
  }

  @Override
  public ActionDao actionDao() {
    return new PostgresActionDao(dataSource, transactionManager);
  }

  @Override
  public CmdletDao cmdletDao() {
    return new PostgresCmdletDao(dataSource, transactionManager);
  }

  @Override
  public SmallFileDao smallFileDao() {
    return new PostgresSmallFileDao(dataSource);
  }

  @Override
  public HmsSyncProgressDao hmsSyncProgressDao() {
    return new PostgresHmsSyncProgressDao(dataSource);
  }
}
