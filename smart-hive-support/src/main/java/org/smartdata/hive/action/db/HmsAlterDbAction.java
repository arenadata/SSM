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

import org.apache.hadoop.hive.metastore.api.Database;
import org.apache.hadoop.hive.metastore.messaging.AlterDatabaseMessage;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hive.action.HmsAction;
import org.smartdata.hive.action.constraint.HmsCreateConstraintAction;

import static org.apache.hadoop.hive.metastore.messaging.EventMessage.EventType.ALTER_DATABASE;

@ActionSignature(
    actionId = HmsAlterDbAction.NAME,
    displayName = HmsAlterDbAction.NAME,
    usage = HmsAlterDbAction.DEST + " $dest "
        + HmsCreateDbAction.NAMESERVICE_RENAME + " $src_ns $trg_ns "
        + HmsCreateConstraintAction.EVENT_MESSAGE + " $message "
)
public class HmsAlterDbAction extends HmsAction {
  public static final String NAME = "hms-alter-db";

  @Override
  protected void execute() throws Exception {
    AlterDatabaseMessage message = parseEventMessage(ALTER_DATABASE);

    Database newDb = message.getDbObjAfter();
    newDb.setLocationUri(renameNameService(newDb.getLocationUri()));

    getMetastoreClient().alterDatabase(message.getDbObjBefore().getName(), newDb);
  }
}
