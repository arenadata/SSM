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
package org.smartdata.hive.action.db;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.metastore.IMetaStoreClient;
import org.apache.hadoop.hive.metastore.api.Database;
import org.apache.hadoop.hive.metastore.api.NoSuchObjectException;
import org.apache.hadoop.hive.metastore.conf.MetastoreConf;
import org.apache.hadoop.hive.metastore.messaging.DropDatabaseMessage;
import org.apache.hadoop.hive.metastore.messaging.EventMessage;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hdfs.impersonation.DisabledUserImpersonationStrategy;
import org.smartdata.hive.HiveSmartConf;
import org.smartdata.hive.action.HmsAction;
import org.smartdata.hive.action.constraint.HmsCreateConstraintAction;
import org.smartdata.hive.client.CachingMetaStoreClientProvider;

@ActionSignature(
    actionId = HmsDropDbAction.NAME,
    displayName = HmsDropDbAction.NAME,
    usage = HmsDropDbAction.DEST + " $dest "
        + HmsDropDbAction.CASCADE
        + HmsCreateConstraintAction.EVENT_MESSAGE + " $message "
)
public class HmsDropDbAction extends HmsAction {
  public static final String NAME = "hms-drop-db";

  @Override
  protected void execute() throws Exception {
    DropDatabaseMessage message = parseEventMessage(
        EventMessage.EventType.DROP_DATABASE);
    appendFormatLog("Dropping database %s", message.getDB());

    if (sourceDatabaseExists(message)) {
      appendFormatLog("Skipping database drop on destination because '%s' still exists on source",
          message.getDB());
      return;
    }

    getMetastoreClient().dropDatabase(
        message.getDB(),
        // deleteData
        false,
        // ignoreUnknownDb
        false,
        // cascade,
        isCascade()
    );

    appendLog("Database was successfully dropped");
  }

  protected boolean sourceDatabaseExists(DropDatabaseMessage message) throws Exception {
    try (IMetaStoreClient sourceMetastoreClient = sourceMetastoreClient()) {
      return sourceDatabaseExists(sourceMetastoreClient, message);
    }
  }

  private boolean sourceDatabaseExists(
      IMetaStoreClient sourceMetastoreClient, DropDatabaseMessage message) throws Exception {
    Database database = message.getDatabaseObject();
    String databaseName = database == null ? message.getDB() : database.getName();
    if (StringUtils.isBlank(databaseName)) {
      throw new IllegalArgumentException("Source event contains empty database name");
    }

    try {
      if (database == null || StringUtils.isBlank(database.getCatalogName())) {
        sourceMetastoreClient.getDatabase(databaseName);
      } else {
        sourceMetastoreClient.getDatabase(database.getCatalogName(), databaseName);
      }
      return true;
    } catch (NoSuchObjectException e) {
      return false;
    }
  }

  private IMetaStoreClient sourceMetastoreClient() {
    HiveSmartConf hiveSmartConf = new HiveSmartConf(getContext().getConf());
    Configuration metastoreConf = MetastoreConf.newMetastoreConf(hiveSmartConf);
    String sourceMetastoreAddress = MetastoreConf.getVar(
        metastoreConf, MetastoreConf.ConfVars.THRIFT_URIS);
    if (StringUtils.isBlank(sourceMetastoreAddress)) {
      throw new IllegalArgumentException("No source metastore address is configured");
    }

    return new CachingMetaStoreClientProvider(
        hiveSmartConf, new DisabledUserImpersonationStrategy())
        .provide(sourceMetastoreAddress, null);
  }
}
