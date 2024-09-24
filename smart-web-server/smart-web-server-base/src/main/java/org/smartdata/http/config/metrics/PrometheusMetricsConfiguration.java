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

import io.micrometer.prometheus.PrometheusMeterRegistry;
import io.prometheus.client.CollectorRegistry;
import org.smartdata.metrics.CompositeMetricsFactory;
import org.smartdata.metrics.MetricsFactory;
import org.springframework.boot.actuate.metrics.export.prometheus.PrometheusScrapeEndpoint;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.smartdata.conf.SmartConfKeys.SMART_METRICS_ENABLED_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_METRICS_PROMETHEUS_ENABLED_KEY;

@Configuration
@ConditionalOnProperty(
    name = {SMART_METRICS_ENABLED_KEY, SMART_METRICS_PROMETHEUS_ENABLED_KEY},
    havingValue = "true",
    matchIfMissing = true
)
public class PrometheusMetricsConfiguration {

  @Bean
  public CollectorRegistry collectorRegistry(MetricsFactory metricsFactory) {
    CompositeMetricsFactory compositeMetricsFactory = (CompositeMetricsFactory) metricsFactory;
    return compositeMetricsFactory.getMeterRegistry()
        .getRegistries()
        .stream()
        .filter(it -> it instanceof PrometheusMeterRegistry)
        .map(PrometheusMeterRegistry.class::cast)
        .map(PrometheusMeterRegistry::getPrometheusRegistry)
        .findFirst()
        .orElse(null);
  }

  @Bean
  public PrometheusScrapeEndpoint prometheusEndpoint(CollectorRegistry collectorRegistry) {
    return new PrometheusScrapeEndpoint(collectorRegistry);
  }
}
