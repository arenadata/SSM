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
package org.smartdata.hive.fetch.ignored;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.hive.metastore.api.Table;
import org.apache.hadoop.hive.metastore.messaging.AlterTableMessage;
import org.smartdata.hive.fetch.HiveEntity;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HiveOperation;
import org.smartdata.hive.fetch.HmsEventStreamRecord;
import org.smartdata.hive.fetch.HmsMessageDeserializers;
import org.smartdata.hive.fetch.filter.HmsEventFilter;
import org.smartdata.hive.snapshot.HiveNotificationEventFactory;

import java.util.Collections;
import java.util.List;

import static org.smartdata.hive.snapshot.HiveNotificationEventFactory.fullName;

/**
 * Handles the ignored table renaming events. If the table was renamed from the name
 * accepted by the event filter to the ignored one, produces the drop event
 * of the table with the previous name.
 *
 * <p>HMS sets only the new table name in the renaming event, so such events are
 * ignored by the event filter, while the table with the previous name should be
 * removed from the events scope. The produced drop event is handled as a regular
 * HMS event, e.g. it's stored and replicated by the HMS sync rules.
 *
 * <p>Tables renamed from the ignored names to the names accepted by the event filter
 * aren't ignored, so they are handled as regular table renaming events.
 */
@Slf4j
public class HmsIgnoredTableRenameHandler implements HmsIgnoredEventHandler {
  private final HmsMessageDeserializers deserializers;
  private final HiveNotificationEventFactory eventFactory;

  public HmsIgnoredTableRenameHandler(HiveNotificationEventFactory eventFactory) {
    this.deserializers = new HmsMessageDeserializers();
    this.eventFactory = eventFactory;
  }

  @Override
  public List<HmsEventStreamRecord> handle(
      HiveNotificationEvent ignoredEvent, HmsEventFilter eventFilter) {
    if (!HiveEntity.TABLE.name().equals(ignoredEvent.getEntityType())
        || !HiveOperation.ALTER.name().equals(ignoredEvent.getEventType())
        || StringUtils.isBlank(ignoredEvent.getMessage())) {
      return Collections.emptyList();
    }

    try {
      AlterTableMessage message = deserializers.forEvent(ignoredEvent)
          .getAlterTableMessage(ignoredEvent.getMessage());

      Table tableBefore = message.getTableObjBefore();
      if (fullName(tableBefore).equals(fullName(message.getTableObjAfter()))) {
        return Collections.emptyList();
      }

      // for the handlers of the events scope, the table renamed
      // out of the scope is the same as the dropped one
      HiveNotificationEvent dropEvent = eventFactory.createDropTableEvent(
          tableBefore, ignoredEvent.getExternalId());
      return eventFilter.test(dropEvent)
          ? Collections.singletonList(dropEvent)
          : Collections.emptyList();
    } catch (Exception e) {
      log.error("Failed to parse ignored event message {}", ignoredEvent, e);
      return Collections.emptyList();
    }
  }
}
