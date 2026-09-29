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

import org.junit.Test;
import org.smartdata.hive.fetch.HmsEventStreamRecord;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.smartdata.hive.handler.HmsEventHandlerChain.bufferingHandlerChain;
import static org.smartdata.hive.handler.HmsEventHandlerChain.handlerChain;

public class HmsEventHandlerChainTest {
  private final List<String> calls = new ArrayList<>();

  @Test
  public void testHandleInOrder() throws Exception {
    HmsEventHandler chain = handlerChain(handler("first"), handler("second"), handler("third"));

    chain.handle(record());

    assertEquals(Arrays.asList("first", "second", "third"), calls);
  }

  @Test
  public void testStopOnFailedHandler() {
    HmsEventHandler chain = handlerChain(handler("first"), failingHandler(), handler("third"));

    assertThrows(IllegalStateException.class, () -> chain.handle(record()));
    assertEquals(Collections.singletonList("first"), calls);
  }

  @Test
  public void testFlushOnlyBufferingHandlers() {
    HmsBufferingEventHandler chain = bufferingHandlerChain(
        bufferingHandler("buffering"), handler("plain"));

    chain.flush();

    assertEquals(Collections.singletonList("buffering.flush"), calls);
  }

  @Test
  public void testReturnHeadWithoutTail() {
    HmsEventHandler head = handler("head");
    HmsBufferingEventHandler bufferingHead = bufferingHandler("head");

    assertSame(head, handlerChain(head));
    assertSame(bufferingHead, bufferingHandlerChain(bufferingHead));
  }

  private HmsEventHandler handler(String name) {
    return record -> calls.add(name);
  }

  private HmsEventHandler failingHandler() {
    return record -> {
      throw new IllegalStateException("failed");
    };
  }

  private HmsBufferingEventHandler bufferingHandler(String name) {
    return new HmsBufferingEventHandler() {
      @Override
      public void handle(HmsEventStreamRecord record) {
        calls.add(name);
      }

      @Override
      public void flush() {
        calls.add(name + ".flush");
      }
    };
  }

  private static HmsEventStreamRecord record() {
    return new HmsEventStreamRecord() {
    };
  }
}
