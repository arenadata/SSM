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
package org.smartdata.test.service;

import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;

import static java.util.concurrent.TimeUnit.SECONDS;

@Slf4j
public class FrequencyTestScheduledService {

  private ScheduledExecutorService scheduler;
  private ScheduledFuture<?> future;

  public void run(Runnable command) {
    scheduler = Executors.newScheduledThreadPool(1);
    future = scheduler.scheduleAtFixedRate(command, 0, 1, SECONDS);
  }

  public void shutdownAndAwaitTermination() {
    future.cancel(true);
    scheduler.shutdown();
    try {
      if (!scheduler.awaitTermination(10, SECONDS)) {
        scheduler.shutdownNow();
        if (!scheduler.awaitTermination(5, SECONDS)) {
          log.error("Pool did not terminate");
        }
      }
    } catch (InterruptedException ie) {
      scheduler.shutdownNow();
      Thread.currentThread().interrupt();
    }
  }
}
