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

import org.smartdata.hive.fetch.BaseHmsEventSource;
import org.smartdata.hive.fetch.HiveNotificationEvent;
import org.smartdata.hive.fetch.HmsEventStreamRecord;
import org.smartdata.hive.fetch.filter.HmsEventFilter;

import java.util.Collections;
import java.util.List;

/**
 * Handles the events rejected by the event filter of the {@link BaseHmsEventSource}.
 *
 * <p>The ignored event itself is always sent to the ignored events queue,
 * while the records returned by the handler are sent to the output queue
 * at the place of the ignored event.
 */
public interface HmsIgnoredEventHandler {
  HmsIgnoredEventHandler NO_OP_HANDLER = (event, filter) -> Collections.emptyList();

  /**
   * @param ignoredEvent event rejected by the filter
   * @param eventFilter filter of the event source, which rejected the event
   * @return records to be sent to the output queue
   */
  List<HmsEventStreamRecord> handle(HiveNotificationEvent ignoredEvent, HmsEventFilter eventFilter);

  static HmsIgnoredEventHandler noOp() {
    return NO_OP_HANDLER;
  }
}
