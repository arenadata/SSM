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
package org.smartdata.hive.fetch.enrich;

import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.hive.metastore.messaging.CreateFunctionMessage;
import org.apache.hadoop.hive.metastore.messaging.DropFunctionMessage;
import org.apache.hadoop.hive.metastore.messaging.MessageEncoder;
import org.smartdata.hive.fetch.HiveEntity;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HiveOperation;

import static org.smartdata.hive.fetch.HiveNotificationEvent.fullResourceName;
import static org.smartdata.hive.fetch.HiveOperation.CREATE;
import static org.smartdata.hive.fetch.HiveOperation.DROP;
import static org.smartdata.hive.snapshot.HiveNotificationEventFactory.fullName;

@Slf4j
public class HmsFunctionNameSetter extends HmsEventModifier {
  public HmsFunctionNameSetter(MessageEncoder messageEncoder) {
    super(messageEncoder, HiveEntity.FUNCTION);
  }

  @Override
  protected HiveNotificationEvent modifyEvent(HiveNotificationEvent event, HiveOperation operation) {
    try {
      if (operation == CREATE) {
        CreateFunctionMessage msg = messageEncoder.getDeserializer()
            .getCreateFunctionMessage(event.getMessage());
        return withNewName(event, fullName(msg.getFunctionObj()));
      }

      if (operation == DROP) {
        DropFunctionMessage msg = messageEncoder.getDeserializer()
            .getDropFunctionMessage(event.getMessage());
        return withNewName(event, fullResourceName(msg.getDB(), msg.getFunctionName()));
      }
    } catch (Exception e) {
      log.error("Failed to parse event message {}", event, e);
    }

    return event;
  }

  private HiveNotificationEvent withNewName(HiveNotificationEvent event, String newName) {
    return event.toBuilder()
        .fullName(newName)
        .build();
  }
}
