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
package org.smartdata.server;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.binder.MeterBinder;
import org.apache.commons.configuration2.SubsetConfiguration;
import org.apache.hadoop.metrics2.AbstractMetric;
import org.apache.hadoop.metrics2.MetricsRecord;
import org.apache.hadoop.metrics2.MetricsSink;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

import static org.smartdata.server.SmartServer.SMART_SERVER_BASE_TAGS;

public class SmartRpcServerMethodMetricsBinder implements MeterBinder, MetricsSink {
  private static final String DETAILED_RPC_RECORD_NAME = "rpcdetailed";
  private static final String NUM_OPS_METRIC_POSTFIX = "NumOps";
  private static final String AVG_TIME_METRIC_POSTFIX = "AvgTime";

  private final Tags baseTags;
  private final Map<String, Double> metricsContainer;

  private MeterRegistry registry;

  public SmartRpcServerMethodMetricsBinder() {
    this(SMART_SERVER_BASE_TAGS);
  }

  public SmartRpcServerMethodMetricsBinder(Tags baseTags) {
    this.baseTags = baseTags;
    this.metricsContainer = new ConcurrentHashMap<>();
  }

  @Override
  public void bindTo(MeterRegistry registry) {
    // save reference to the registry for lazy gauge creation
    this.registry = registry;
  }

  @Override
  public void putMetrics(MetricsRecord record) {
    if (record.name().equals(DETAILED_RPC_RECORD_NAME)) {
      record.metrics().forEach(this::handleMetric);
    }
  }

  public void handleMetric(AbstractMetric metric) {
    metricsContainer.computeIfAbsent(metric.name(), this::createRpcMethodGauge);
    metricsContainer.put(metric.name(), metric.value().doubleValue());
  }

  private Double createRpcMethodGauge(String metricName) {
    Supplier<Number> gaugeProvider =
        () -> metricsContainer.getOrDefault(metricName, 0.0);

    if (metricName.endsWith(NUM_OPS_METRIC_POSTFIX)) {
      Gauge.builder("rpc.method.calls.total", gaugeProvider)
          .tags(Tags.concat(baseTags, "method",
              metricName.replace(NUM_OPS_METRIC_POSTFIX, "")))
          .description("Total number of the times the RPC method is called")
          .register(registry);
    } else {
      Gauge.builder("rpc.method.call.time.average.ms", gaugeProvider)
          .tags(Tags.concat(baseTags, "method",
              metricName.replace(AVG_TIME_METRIC_POSTFIX, "")))
          .description("Average turn around time of the RPC method in milliseconds")
          .register(registry);
    }

    return 0.0;
  }

  @Override
  public void flush() {

  }

  @Override
  public void init(SubsetConfiguration conf) {

  }
}
