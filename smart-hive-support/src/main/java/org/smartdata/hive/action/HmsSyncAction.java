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
package org.smartdata.hive.action;

import org.smartdata.action.annotation.ActionSignature;

@ActionSignature(
    actionId = HmsSyncAction.NAME,
    displayName = HmsSyncAction.NAME,
    usage = HmsSyncAction.DEST + " $dest "
        + HmsSyncAction.NAMESERVICE_RENAME + " $src_ns $trg_ns "
        + HmsSyncAction.CASCADE
)
public class HmsSyncAction extends HmsAction {
  public static final String NAME = "hms-sync";
  public static final String ENTITY_NAME = "-entityName";
  public static final String RELATED_RESOURCES = "-relatedResources";

  public static final String INCLUDE = "-include";
  public static final String EXCLUDE = "-exclude";

  @Override
  protected void execute() throws Exception {
    // do nothing, it's a pseudo-action for HMS sync
  }
}
