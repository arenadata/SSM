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
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.composite.CompositeMeterRegistry;
import org.smartdata.conf.SmartConf;

import java.util.concurrent.ScheduledExecutorService;

import static org.smartdata.conf.SmartConfKeys.SMART_METRICS_ENABLED_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_METRICS_ENABLED_KEY;

public interface MetricsFactory extends AutoCloseable {

  CompositeMeterRegistry getMeterRegistry();

  Counter counter(String name, String... tags);

  ScheduledExecutorService wrap(ScheduledExecutorService executorService, String name, String... tags);

  static MetricsFactory noOp() {
    return new NoOpMetricsFactory();
  }

  static MetricsFactory from(SmartConf conf, Tags baseTags) {
    return conf.getBoolean(SMART_METRICS_ENABLED_KEY, SMART_METRICS_ENABLED_DEFAULT)
        ? CompositeMetricsFactory.from(conf, baseTags)
        : MetricsFactory.noOp();
  }
}
