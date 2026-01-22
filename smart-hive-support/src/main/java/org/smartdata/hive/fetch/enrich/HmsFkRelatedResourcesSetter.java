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
import org.apache.commons.collections4.CollectionUtils;
import org.apache.hadoop.hive.metastore.api.SQLForeignKey;
import org.apache.hadoop.hive.metastore.messaging.AddForeignKeyMessage;
import org.apache.hadoop.hive.metastore.messaging.MessageEncoder;
import org.smartdata.hive.fetch.HiveEntity;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HiveOperation;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.smartdata.hive.fetch.HiveNotificationEvent.fullResourceName;
import static org.smartdata.hive.fetch.HiveOperation.CREATE;

@Slf4j
public class HmsFkRelatedResourcesSetter extends HmsEventModifier {
  public HmsFkRelatedResourcesSetter(MessageEncoder messageEncoder) {
    super(messageEncoder, HiveEntity.FOREIGN_KEY);
  }

  @Override
  protected HiveNotificationEvent modifyEvent(HiveNotificationEvent event, HiveOperation operation) {
    try {
      if (operation == CREATE) {
        AddForeignKeyMessage msg = messageEncoder.getDeserializer()
            .getAddForeignKeyMessage(event.getMessage());

        List<SQLForeignKey> foreignKeys = msg.getForeignKeys();
        if (CollectionUtils.isEmpty(foreignKeys)) {
          return event;
        }

        Set<String> relatedResources = foreignKeys.stream()
            .map(key -> fullResourceName(key.getFktable_db(), key.getFktable_name()))
            .collect(Collectors.toSet());

        return event.toBuilder()
            .relatedResources(relatedResources)
            .build();
      }
    } catch (Exception e) {
      log.error("Failed to parse event message {}", event, e);
    }

    return event;
  }
}
