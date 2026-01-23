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

import org.apache.hadoop.hive.metastore.messaging.AddCheckConstraintMessage;
import org.apache.hadoop.hive.metastore.messaging.AddDefaultConstraintMessage;
import org.apache.hadoop.hive.metastore.messaging.AddForeignKeyMessage;
import org.apache.hadoop.hive.metastore.messaging.AddNotNullConstraintMessage;
import org.apache.hadoop.hive.metastore.messaging.AddPrimaryKeyMessage;
import org.apache.hadoop.hive.metastore.messaging.AddUniqueConstraintMessage;
import org.apache.hadoop.hive.metastore.messaging.EventMessage;
import org.smartdata.action.annotation.ActionSignature;
import org.smartdata.hive.action.HmsAction;
import org.smartdata.hive.fetch.HiveEntity;

import java.util.Optional;

@ActionSignature(
    actionId = HmsCreateConstraintAction.NAME,
    displayName = HmsCreateConstraintAction.NAME,
    usage = HmsCreateConstraintAction.DEST + " $dest "
        + HmsCreateConstraintAction.TYPE + " $type "
        + HmsCreateConstraintAction.EVENT_MESSAGE + " $message "
)
public class HmsCreateConstraintAction extends HmsAction {
  public static final String NAME = "hms-create-constraint";
  public static final String TYPE = "-type";

  @Override
  protected void execute() throws Exception {
    HiveEntity constraintType = getConstraintType();
    switch (constraintType) {
      case PRIMARY_KEY:
        handlePrimaryKey();
        break;
      case FOREIGN_KEY:
        handleForeignKey();
        break;
      case UNIQUE_CONSTRAINT:
        handleUniqueConstraint();
        break;
      case NOT_NULL_CONSTRAINT:
        handleNotNullConstraint();
        break;
      case DEFAULT_CONSTRAINT:
        handleDefaultConstraint();
        break;
      case CHECK_CONSTRAINT:
        handleCheckConstraint();
        break;
      default:
        throw new IllegalArgumentException("Invalid constraint type: " + constraintType);
    }

    appendLog("Constraint was successfully created");
  }

  private void handlePrimaryKey() throws Exception {
    AddPrimaryKeyMessage message = parseEventMessage(
        EventMessage.EventType.ADD_PRIMARYKEY);

    appendLog("Creating primary key");
    getMetastoreClient().addPrimaryKey(message.getPrimaryKeys());
  }

  private void handleForeignKey() throws Exception {
    AddForeignKeyMessage message = parseEventMessage(
        EventMessage.EventType.ADD_FOREIGNKEY);

    appendLog("Creating foreign key");
    getMetastoreClient().addForeignKey(message.getForeignKeys());
  }

  private void handleUniqueConstraint() throws Exception {
    AddUniqueConstraintMessage message = parseEventMessage(
        EventMessage.EventType.ADD_UNIQUECONSTRAINT);

    appendLog("Creating unique constraint");
    getMetastoreClient().addUniqueConstraint(message.getUniqueConstraints());
  }

  private void handleNotNullConstraint() throws Exception {
    AddNotNullConstraintMessage message = parseEventMessage(
        EventMessage.EventType.ADD_NOTNULLCONSTRAINT);

    appendLog("Creating not null constraint");
    getMetastoreClient().addNotNullConstraint(message.getNotNullConstraints());
  }

  private void handleDefaultConstraint() throws Exception {
    AddDefaultConstraintMessage message = parseEventMessage(
        EventMessage.EventType.ADD_DEFAULTCONSTRAINT);

    appendLog("Creating default constraint");
    getMetastoreClient().addDefaultConstraint(message.getDefaultConstraints());
  }

  private void handleCheckConstraint() throws Exception {
    AddCheckConstraintMessage message = parseEventMessage(
        EventMessage.EventType.ADD_CHECKCONSTRAINT);

    appendLog("Creating check constraint");
    getMetastoreClient().addCheckConstraint(message.getCheckConstraints());
  }

  private HiveEntity getConstraintType() {
    return Optional.ofNullable(getArguments().get(TYPE))
        .map(HiveEntity::valueOf)
        .orElseThrow(() -> new IllegalArgumentException("No operation type provided"));
  }
}
