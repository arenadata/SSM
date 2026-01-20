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
package org.smartdata.hive.action.partition;

import org.apache.hadoop.hive.metastore.api.Partition;
import org.apache.hadoop.hive.metastore.messaging.AlterPartitionMessage;
import org.apache.hadoop.hive.metastore.messaging.EventMessage;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hive.action.HmsAction;
import org.smartdata.hive.action.constraint.HmsCreateConstraintAction;

import java.util.Objects;

@ActionSignature(
    actionId = HmsAlterPartitionAction.NAME,
    displayName = HmsAlterPartitionAction.NAME,
    usage = HmsAlterPartitionAction.DEST + " $dest "
        + HmsAlterPartitionAction.NAMESERVICE_RENAME + " $src_ns $trg_ns "
        + HmsCreateConstraintAction.EVENT_MESSAGE + " $message "
)
public class HmsAlterPartitionAction extends HmsAction {
  public static final String NAME = "hms-alter-partition";

  @Override
  protected void execute() throws Exception {
    AlterPartitionMessage message = parseEventMessage(
        EventMessage.EventType.ALTER_PARTITION);
    Partition oldPartition = message.getPtnObjBefore();
    Partition partition = message.getPtnObjAfter();

    appendFormatLog("Altering partition %s for table %s.%s",
        oldPartition.getValues(),
        oldPartition.getDbName(),
        oldPartition.getTableName());

    renameNameService(partition.getSd());

    if (Objects.equals(oldPartition.getValues(), partition.getValues())) {
      getMetastoreClient().alter_partition(
            oldPartition.getDbName(),
            oldPartition.getTableName(),
            partition
      );
    } else {
      getMetastoreClient().renamePartition(
            oldPartition.getCatName(),
            oldPartition.getDbName(),
            oldPartition.getTableName(),
            oldPartition.getValues(),
            partition,
            null
      );
    }

    appendLog("Partitions was successfully altered");
  }
}
