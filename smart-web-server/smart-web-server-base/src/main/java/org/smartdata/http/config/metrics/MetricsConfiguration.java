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
package org.smartdata.http.config.metrics;

import io.micrometer.core.instrument.MeterRegistry;
import org.smartdata.metrics.MetricsFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import static org.smartdata.conf.SmartConfKeys.SMART_METRICS_ENABLED_KEY;

@Configuration
@ConditionalOnProperty(
    name = SMART_METRICS_ENABLED_KEY,
    havingValue = "true",
    matchIfMissing = true
)
public class MetricsConfiguration {
  @Bean
  @Primary
  public MeterRegistry meterRegistry(MetricsFactory metricsFactory) {
    return metricsFactory.getMeterRegistry();
  }
}
