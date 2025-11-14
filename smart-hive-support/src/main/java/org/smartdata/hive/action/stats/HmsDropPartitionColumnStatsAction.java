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
package org.smartdata.hive.action.stats;

import org.apache.hadoop.hive.metastore.messaging.DeletePartitionColumnStatMessage;
import org.apache.hadoop.hive.metastore.messaging.EventMessage;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hive.action.HmsAction;
import org.smartdata.hive.action.constraint.HmsCreateConstraintAction;

@ActionSignature(
    actionId = HmsDropPartitionColumnStatsAction.NAME,
    displayName = HmsDropPartitionColumnStatsAction.NAME,
    usage = HmsDropPartitionColumnStatsAction.DEST + " $dest "
        + HmsCreateConstraintAction.EVENT_MESSAGE + " message "
        + HmsDropPartitionColumnStatsAction.TABLE_NAME + " table "
)
public class HmsDropPartitionColumnStatsAction extends HmsAction {
  public static final String NAME = "hms-drop-partition-column-stats";

  @Override
  protected void execute() throws Exception {
    DeletePartitionColumnStatMessage message = parseEventMessage(
        EventMessage.EventType.DELETE_PARTITION_COLUMN_STAT);

    appendFormatLog("Dropping column stats of partition column %s.%s.%s.%s",
        message.getDB(), getTableName(), message.getPartName(), message.getColName());

    getMetastoreClient().deletePartitionColumnStatistics(
        message.getDB(), getTableName(), message.getPartName(), message.getColName(), null);

    appendLog("Table column stats were successfully updated");
  }
}
