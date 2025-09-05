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

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.smartdata.hive.HmsEventDao;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HmsEventStreamRecord;
import org.smartdata.retry.RetrySupport;

@Slf4j
@RequiredArgsConstructor
public class DbHmsEventHandler implements HmsEventHandler {
  private final HmsEventDao hmsEventDao;
  private final RetrySupport retrySupport;

  @Override
  public void handle(HmsEventStreamRecord record) throws Exception {
    retrySupport.withRetries(() -> handleEventAction(record));
  }

  private void handleEventAction(HmsEventStreamRecord record) {
    if (record instanceof HiveNotificationEvent) {
      hmsEventDao.insert((HiveNotificationEvent) record);
    } else {
      log.warn("Unsupported event type: {}", record.getClass().getName());
    }
  }
}
