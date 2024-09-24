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
package org.smartdata.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.composite.CompositeMeterRegistry;
import io.micrometer.core.instrument.noop.NoopCounter;
import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.ScheduledExecutorService;


@Slf4j
public class NoOpMetricsFactory implements MetricsFactory {

  private final Counter counter;

  public NoOpMetricsFactory() {
    this.counter = new NoopCounter(id("no-op-counter"));
  }

  @Override
  public CompositeMeterRegistry getMeterRegistry() {
    return new CompositeMeterRegistry();
  }

  @Override
  public Counter counter(String name, String... tags) {
    return counter;
  }

  @Override
  public ScheduledExecutorService wrap(ScheduledExecutorService executorService, String name, String... tags) {
    return executorService;
  }

  @Override
  public void close() throws Exception {

  }

  private Meter.Id id(String name) {
    return new Meter.Id(name, Tags.empty(), null, null, Meter.Type.OTHER);
  }
}
