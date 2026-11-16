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

import org.apache.commons.lang3.ArrayUtils;
import org.smartdata.hive.fetch.HmsEventStreamRecord;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Passes each record to all handlers in the order they were provided.
 * If any handler fails, the record isn't passed to the following handlers.
 */
public class HmsEventHandlerChain implements HmsBufferingEventHandler {
  private final List<HmsEventHandler> handlers;

  HmsEventHandlerChain(HmsEventHandler head, HmsEventHandler... tail) {
    this.handlers = new ArrayList<>();
    this.handlers.add(head);
    this.handlers.addAll(Arrays.asList(tail));
  }

  @Override
  public void handle(HmsEventStreamRecord record) throws Exception {
    for (HmsEventHandler handler : handlers) {
      handler.handle(record);
    }
  }

  @Override
  public void flush() {
    for (HmsEventHandler handler : handlers) {
      if (handler instanceof HmsBufferingEventHandler) {
        ((HmsBufferingEventHandler) handler).flush();
      }
    }
  }

  public static HmsEventHandler handlerChain(
      HmsEventHandler head, HmsEventHandler... tail) {
    return ArrayUtils.isEmpty(tail) ? head : new HmsEventHandlerChain(head, tail);
  }

  public static HmsBufferingEventHandler bufferingHandlerChain(
      HmsBufferingEventHandler head, HmsEventHandler... tail) {
    return ArrayUtils.isEmpty(tail) ? head : new HmsEventHandlerChain(head, tail);
  }
}
