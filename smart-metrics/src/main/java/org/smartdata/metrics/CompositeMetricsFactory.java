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

import io.micrometer.core.instrument.Clock;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.binder.MeterBinder;
import io.micrometer.core.instrument.binder.jvm.ClassLoaderMetrics;
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmGcMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmHeapPressureMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmThreadMetrics;
import io.micrometer.core.instrument.binder.system.FileDescriptorMetrics;
import io.micrometer.core.instrument.binder.system.ProcessorMetrics;
import io.micrometer.core.instrument.binder.system.UptimeMetrics;
import io.micrometer.core.instrument.composite.CompositeMeterRegistry;
import io.micrometer.jmx.JmxConfig;
import io.micrometer.jmx.JmxMeterRegistry;
import io.micrometer.prometheus.PrometheusConfig;
import io.micrometer.prometheus.PrometheusMeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.smartdata.conf.SmartConf;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.stream.Collectors;

import static org.smartdata.conf.SmartConfKeys.SMART_METRICS_JMX_DOMAIN_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_METRICS_JMX_DOMAIN_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_METRICS_JMX_ENABLED_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_METRICS_JMX_ENABLED_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_METRICS_PROMETHEUS_ENABLED_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_METRICS_PROMETHEUS_ENABLED_KEY;

@Slf4j
public class CompositeMetricsFactory implements MetricsFactory {
  private final CompositeMeterRegistry compositeMeterRegistry;

  private final Iterable<AutoCloseable> resources;
  private final Tags baseTags;

  public CompositeMetricsFactory(Iterable<MeterRegistry> registries, Tags baseTags) {
    this(
        new CompositeMeterRegistry(Clock.SYSTEM, registries),
        Arrays.asList(
            new ProcessorMetrics(),
            new UptimeMetrics(),
            new JvmGcMetrics(),
            new JvmMemoryMetrics(),
            new FileDescriptorMetrics(),
            new ClassLoaderMetrics(),
            new JvmHeapPressureMetrics(),
            new JvmThreadMetrics()),
        baseTags);
  }

  public CompositeMetricsFactory(CompositeMeterRegistry compositeRegistry,
                                 Collection<MeterBinder> defaultMetrics,
                                 Tags baseTags) {
    this.compositeMeterRegistry = compositeRegistry;
    this.baseTags = baseTags;
    this.resources = defaultMetrics.stream()
        .filter(metric -> metric instanceof AutoCloseable)
        .map(AutoCloseable.class::cast)
        .collect(Collectors.toList());
    defaultMetrics
        .forEach(metric -> metric.bindTo(compositeMeterRegistry));
  }

  @Override
  public CompositeMeterRegistry getMeterRegistry() {
    return compositeMeterRegistry;
  }

  @Override
  public Counter counter(String name, String... tags) {
    return compositeMeterRegistry.counter(name, Tags.concat(baseTags, tags));
  }

  @Override
  public ScheduledExecutorService wrap(ScheduledExecutorService executorService, String name, String... tags) {
    return ExecutorServiceMetrics.monitor(compositeMeterRegistry,
        executorService, name, Tags.concat(baseTags, tags));
  }

  @Override
  public void close() throws Exception {
    for (AutoCloseable closeable : resources) {
      try {
        closeable.close();
      } catch (Exception e) {
        log.error("Error closing resource", e);
      }
    }
  }

  public static MetricsFactory from(SmartConf conf, Tags baseTags) {
    List<MeterRegistry> registries = new ArrayList<>();

    boolean prometheusEnabled = conf.getBoolean(
        SMART_METRICS_PROMETHEUS_ENABLED_KEY, SMART_METRICS_PROMETHEUS_ENABLED_DEFAULT);
    if (prometheusEnabled) {
      registries.add(new PrometheusMeterRegistry(PrometheusConfig.DEFAULT));
    }

    boolean jmxEnabled = conf.getBoolean(
        SMART_METRICS_JMX_ENABLED_KEY, SMART_METRICS_JMX_ENABLED_DEFAULT);
    if (jmxEnabled) {
      registries.add(new JmxMeterRegistry(new SsmJmxConfig(conf), Clock.SYSTEM));
    }

    if (registries.isEmpty()) {
      log.warn("No metrics exporters are provided, although metrics collection is enabled. "
          + "Switching to no-op implementation");
      return MetricsFactory.noOp();
    }

    return new CompositeMetricsFactory(registries, baseTags);
  }

  private static class SsmJmxConfig implements JmxConfig {

    private final String domain;

    private SsmJmxConfig(SmartConf conf) {
      this.domain = conf.get(
          SMART_METRICS_JMX_DOMAIN_KEY,
          SMART_METRICS_JMX_DOMAIN_DEFAULT);
    }

    public String domain() {
      return domain;
    }

    @Override
    public String get(String key) {
      return null;
    }
  }

}
