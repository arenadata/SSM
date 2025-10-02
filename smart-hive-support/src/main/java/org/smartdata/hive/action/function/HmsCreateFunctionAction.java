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
package org.smartdata.hive.action.function;

import org.apache.hadoop.hive.metastore.api.Function;
import org.apache.hadoop.hive.metastore.messaging.CreateFunctionMessage;
import org.apache.hadoop.hive.metastore.messaging.EventMessage;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hive.action.HmsAction;
import org.smartdata.hive.action.constraint.HmsCreateConstraintAction;

@ActionSignature(
    actionId = HmsCreateFunctionAction.NAME,
    displayName = HmsCreateFunctionAction.NAME,
    usage = HmsCreateFunctionAction.DEST + " $dest "
        + HmsCreateFunctionAction.NAMESERVICE_RENAME + " $src_ns $trg_ns "
        + HmsCreateConstraintAction.EVENT_MESSAGE + " $message "
)
public class HmsCreateFunctionAction extends HmsAction {
  public static final String NAME = "hms-create-function";

  @Override
  protected void execute() throws Exception {
    CreateFunctionMessage message = parseEventMessage(
        EventMessage.EventType.CREATE_FUNCTION);

    Function function = message.getFunctionObj();
    updateResourceLocations(function);

    getMetastoreClient().createFunction(function);
  }

  private void updateResourceLocations(Function function) {
    function.getResourceUris()
        .forEach(resourceUri ->
            resourceUri.setUri(renameNameService(resourceUri.getUri())));
  }
}
