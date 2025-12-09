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

import org.apache.hadoop.hive.metastore.messaging.DropPartitionMessage;
import org.apache.hadoop.hive.metastore.messaging.EventMessage;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hive.action.HmsAction;
import org.smartdata.hive.action.constraint.HmsCreateConstraintAction;

import java.util.ArrayList;
import java.util.Map;

@ActionSignature(
    actionId = HmsDropPartitionAction.NAME,
    displayName = HmsDropPartitionAction.NAME,
    usage = HmsDropPartitionAction.DEST + " $dest "
        + HmsCreateConstraintAction.EVENT_MESSAGE + " $message "
)
public class HmsDropPartitionAction extends HmsAction {
  public static final String NAME = "hms-drop-partition";

  @Override
  protected void execute() throws Exception {
    DropPartitionMessage message = parseEventMessage(
        EventMessage.EventType.DROP_PARTITION);
    appendFormatLog("Dropping partition for table %s%s",
        message.getDB(),
        message.getTable());

    // todo currently MetastoreClient API only exposes
    //  partition bulk removal methods with filters of internal
    //  format. It was fixed in the version 4.2.0 (HIVE-28219),
    //  so we need to use it, when we bump the version of Hive.
    //  For now, simply remove partitions one by one
    for (Map<String, String> partition : message.getPartitions()) {
      ArrayList<String> partitionValues = new ArrayList<>(partition.values());
      appendFormatLog("Dropping partition: %s", partitionValues);

      getMetastoreClient().dropPartition(
          message.getDB(),
          message.getTable(),
          partitionValues,
          // deleteData
          false
      );
    }

    appendLog("Partitions were successfully dropped");
  }
}
