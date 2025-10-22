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
package org.smartdata.hive.handler;

import com.google.common.collect.ImmutableMap;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.EnumUtils;
import org.apache.hadoop.hive.metastore.messaging.AlterDatabaseMessage;
import org.apache.hadoop.hive.metastore.messaging.AlterPartitionMessage;
import org.apache.hadoop.hive.metastore.messaging.AlterTableMessage;
import org.smartdata.hive.HmsEventDao;
import org.smartdata.hive.fetch.HiveEntity;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HmsEventStreamRecord;
import org.smartdata.hive.snapshot.HiveNotificationEventFactory;

import java.util.Collection;
import java.util.Comparator;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Slf4j
public class HmsIntermediateEventsResolver implements HmsBufferingEventHandler {
  private final HmsEventDao eventDao;
  private final HiveNotificationEventFactory eventFactory;

  private final Map<HiveEntity, HmsEntityIntermediateEventsResolver> resolvers;
  private final DefaultEventResolver defaultResolver;

  public HmsIntermediateEventsResolver(HmsEventDao eventDao,
      HiveNotificationEventFactory eventFactory) {
    this.eventDao = eventDao;
    this.eventFactory = eventFactory;
    this.defaultResolver = new DefaultEventResolver();
    this.resolvers = ImmutableMap.of(
        HiveEntity.DATABASE, new DbEventResolver(),
        HiveEntity.TABLE, new TableEventResolver(),
        HiveEntity.PARTITION, new PartitionEventResolver()
    );
  }

  @Override
  public void handle(HmsEventStreamRecord record) throws Exception {
    if (record.isLastRecord()) {
      return;
    }

    if (!(record instanceof HiveNotificationEvent)) {
      throw new IllegalArgumentException("Unexpected record type: " + record.getClass().getName());
    }

    HiveNotificationEvent event = (HiveNotificationEvent) record;
    HiveEntity hiveEntity = Optional.ofNullable(event.getEntityType())
        .map(type -> EnumUtils.getEnum(HiveEntity.class, type))
        .orElseThrow(() -> new IllegalArgumentException("Unexpected event with unknown entity type: " + event));

    resolvers.getOrDefault(hiveEntity, defaultResolver).handle(event);
  }

  public void flush() {
    eventDao.executeWithoutResult(ignore -> flushAction());
  }

  private void flushAction() {
    resolvers.values()
        .stream()
        .map(HmsEntityIntermediateEventsResolver::getEntityNamesToDelete)
        .flatMap(Set::stream)
        .peek(entityName -> log.info("Intermediate Hive event resolving: deleting entity {}", entityName))
        .forEach(eventDao::deleteEventsFor);

    resolvers.values()
        .stream()
        .map(HmsEntityIntermediateEventsResolver::getEntitiesToCreate)
        .map(Map::values)
        .flatMap(Collection::stream)
        .sorted(Comparator.comparingLong(HiveNotificationEvent::getExternalId))
        .peek(event -> log.info("Intermediate Hive event resolving: inserting event {}", event))
        .forEach(eventDao::insertIfNotPresent);
  }

  private class DbEventResolver extends HmsEntityIntermediateEventsResolver {
    @Override
    protected HiveNotificationEvent getUpdatedEvent(HiveNotificationEvent event) throws Exception {
      AlterDatabaseMessage message = eventFactory.getMessageEncoder()
          .getDeserializer()
          .getAlterDatabaseMessage(event.getMessage());
      return eventFactory.createDbEvent(message.getDbObjAfter(), event.getExternalId());
    }
  }

  private class TableEventResolver extends HmsEntityIntermediateEventsResolver {
    @Override
    protected HiveNotificationEvent getUpdatedEvent(HiveNotificationEvent event) throws Exception {
      AlterTableMessage message = eventFactory.getMessageEncoder()
          .getDeserializer()
          .getAlterTableMessage(event.getMessage());
      return eventFactory.createTableEvent(message.getTableObjAfter(), event.getExternalId());
    }
  }

  private class PartitionEventResolver extends HmsEntityIntermediateEventsResolver {
    @Override
    protected HiveNotificationEvent getUpdatedEvent(HiveNotificationEvent event) throws Exception {
      AlterPartitionMessage message = eventFactory.getMessageEncoder()
          .getDeserializer()
          .getAlterPartitionMessage(event.getMessage());
      return eventFactory.createPartitionEvent(
          message.getTableObj(), message.getPtnObjAfter(), event.getExternalId());
    }
  }

  // for entity types that don't support alter operations
  private static class DefaultEventResolver extends HmsEntityIntermediateEventsResolver {
    @Override
    protected HiveNotificationEvent getUpdatedEvent(HiveNotificationEvent event) {
      return event;
    }
  }
}
