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
package org.smartdata.hive.fetch;

import org.apache.hadoop.hive.metastore.messaging.MessageDeserializer;
import org.apache.hadoop.hive.metastore.messaging.MessageFactory;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Provides HMS message deserializers based on the format of the event message,
 * since HMS can be configured to use different message encoders.
 */
public class HmsMessageDeserializers {
  private final Map<String, MessageDeserializer> deserializers = new ConcurrentHashMap<>();

  public MessageDeserializer forEvent(HiveNotificationEvent event) {
    return Optional.ofNullable(event.getMessageFormat())
        .map(format -> deserializers.computeIfAbsent(format, this::createDeserializer))
        .orElseThrow(() -> new IllegalArgumentException("HMS event message format is not specified"));
  }

  private MessageDeserializer createDeserializer(String messageFormat) {
    try {
      return MessageFactory.getInstance(messageFormat).getDeserializer();
    } catch (Exception e) {
      throw new IllegalArgumentException("Unsupported HMS event message format: " + messageFormat, e);
    }
  }
}
