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
package org.smartdata.hive.action.table;

import org.apache.hadoop.hive.metastore.api.Table;
import org.apache.hadoop.hive.metastore.messaging.CreateTableMessage;
import org.apache.hadoop.hive.metastore.messaging.EventMessage;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hive.action.HmsAction;
import org.smartdata.hive.action.constraint.HmsCreateConstraintAction;

@ActionSignature(
    actionId = HmsCreateTableAction.NAME,
    displayName = HmsCreateTableAction.NAME,
    usage = HmsCreateTableAction.DEST + " $dest "
        + HmsCreateTableAction.NAMESERVICE_RENAME + " $src_ns $trg_ns "
        + HmsCreateConstraintAction.EVENT_MESSAGE + " $message "
)
public class HmsCreateTableAction extends HmsAction {
  public static final String NAME = "hms-create-table";

  @Override
  protected void execute() throws Exception {
    CreateTableMessage message = parseEventMessage(
        EventMessage.EventType.CREATE_TABLE);

    appendFormatLog("Creating table %s.%s",
        message.getDB(),
        message.getTable());

    Table table = message.getTableObj();
    renameNameService(table.getSd());

    getMetastoreClient().createTable(table);

    appendLog("Table was successfully created");
  }
}
