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

import org.apache.hadoop.hive.common.TableName;
import org.apache.hadoop.hive.metastore.api.FieldSchema;
import org.apache.hadoop.hive.metastore.api.Table;
import org.apache.hadoop.hive.metastore.messaging.AlterTableMessage;
import org.apache.hadoop.hive.metastore.messaging.EventMessage;
import org.apache.thrift.TException;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hive.action.HmsAction;
import org.smartdata.hive.action.constraint.HmsCreateConstraintAction;

import java.util.List;
import java.util.stream.Collectors;

@ActionSignature(
    actionId = HmsAlterTableAction.NAME,
    displayName = HmsAlterTableAction.NAME,
    usage = HmsAlterTableAction.DEST + " $dest "
        + HmsAlterTableAction.NAMESERVICE_RENAME + " $src_ns $trg_ns "
        + HmsCreateConstraintAction.EVENT_MESSAGE + " $message "
)
public class HmsAlterTableAction extends HmsAction {
  public static final String NAME = "hms-alter-table";

  @Override
  protected void execute() throws Exception {
    AlterTableMessage message = parseEventMessage(
        EventMessage.EventType.ALTER_TABLE);

    Table table = message.getTableObjAfter();
    renameNameService(table.getSd());

    appendFormatLog("Altering table %s.%s",
        message.getDB(),
        table.getTableName());

    if (message.getIsTruncateOp()) {
      truncateTable(message.getTableObjBefore());
      return;
    }

    Table oldTable = message.getTableObjBefore();
    getMetastoreClient().alter_table(oldTable.getDbName(), oldTable.getTableName(), table);

    appendLog("Table was successfully altered");
  }

  private void truncateTable(Table table) throws TException {
    List<String> partitionNames = table.getPartitionKeys()
        .stream()
        .map(FieldSchema::getName)
        .collect(Collectors.toList());

    getMetastoreClient().truncateTable(
        TableName.fromString(
            table.getCatName(),
            table.getDbName(),
            table.getTableName()
        ), partitionNames);

    appendLog("Table was successfully truncated");
  }
}
