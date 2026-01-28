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

import com.google.common.collect.Sets;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.EnumUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.hive.metastore.messaging.MessageEncoder;
import org.smartdata.hive.fetch.HiveEntity;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HiveOperation;

import java.util.Optional;
import java.util.Set;

@Slf4j
public abstract class HmsEventModifier implements HmsEventEnricher {
  private final Set<HiveEntity> supportedEntities;
  protected final MessageEncoder messageEncoder;

  public HmsEventModifier(MessageEncoder messageEncoder, HiveEntity... supportedEntities) {
    this.messageEncoder = messageEncoder;
    this.supportedEntities = Sets.newHashSet(supportedEntities);
  }

  @Override
  public HiveNotificationEvent enrich(HiveNotificationEvent event) {
    return Optional.ofNullable(event.getEntityType())
        .map(type -> EnumUtils.getEnum(HiveEntity.class, type))
        .filter(supportedEntities::contains)
        .flatMap(ignore -> modifyEvent(event))
        .orElse(event);
  }

  protected abstract HiveNotificationEvent modifyEvent(
      HiveNotificationEvent event,
      HiveOperation operation);

  private Optional<HiveNotificationEvent> modifyEvent(HiveNotificationEvent event) {
    if (StringUtils.isBlank(event.getMessage())) {
      return Optional.empty();
    }

    return Optional.ofNullable(event.getEventType())
        .map(type -> EnumUtils.getEnum(HiveOperation.class, type))
        .map(operation -> modifyEvent(event, operation));
  }
}
