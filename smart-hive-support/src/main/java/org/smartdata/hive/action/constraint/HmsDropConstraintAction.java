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
package org.smartdata.hive.action.constraint;

import org.apache.hadoop.hive.metastore.messaging.DropConstraintMessage;
import org.apache.hadoop.hive.metastore.messaging.EventMessage;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hive.action.HmsAction;

@ActionSignature(
    actionId = HmsDropConstraintAction.NAME,
    displayName = HmsDropConstraintAction.NAME,
    usage = HmsDropConstraintAction.DEST + " $dest "
        + HmsCreateConstraintAction.EVENT_MESSAGE + " $message "
)
public class HmsDropConstraintAction extends HmsAction {
  public static final String NAME = "hms-drop-constraint";

  @Override
  protected void execute() throws Exception {
    DropConstraintMessage message = parseEventMessage(
        EventMessage.EventType.DROP_CONSTRAINT);
    appendFormatLog("Dropping constraint %s for table %s.%s",
        message.getConstraint(),
        message.getDB(),
        message.getTable());

    getMetastoreClient().dropConstraint(
        message.getDB(),
        message.getTable(),
        message.getConstraint());

    appendLog("Constraint was successfully dropped");
  }
}
