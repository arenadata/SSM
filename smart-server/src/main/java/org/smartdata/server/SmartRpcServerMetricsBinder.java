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
import org.apache.hadoop.metrics2.MetricsRecord;
import org.apache.hadoop.metrics2.MetricsSink;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

import static org.smartdata.server.SmartServer.SMART_SERVER_BASE_TAGS;

public class SmartRpcServerMetricsBinder implements MeterBinder, MetricsSink {
  private static final String RPC_RECORD_NAME = "rpc";

  private final Tags baseTags;
  private final Map<String, Double> metricsContainer;

  public SmartRpcServerMetricsBinder() {
    this(SMART_SERVER_BASE_TAGS);
  }

  public SmartRpcServerMetricsBinder(Tags baseTags) {
    this.baseTags = baseTags;
    this.metricsContainer = new ConcurrentHashMap<>();
  }

  @Override
  public void bindTo(MeterRegistry registry) {
    Gauge.builder("rpc.bytes.received", metricProvider("ReceivedBytes"))
        .tags(baseTags)
        .description("Total number of received bytes by RPC server")
        .register(registry);

    Gauge.builder("rpc.bytes.sent", metricProvider("SentBytes"))
        .tags(baseTags)
        .description("Total number of sent bytes by RPC server")
        .register(registry);

    Gauge.builder("rpc.calls.total", metricProvider("RpcQueueTimeNumOps"))
        .tags(baseTags)
        .description("Total number of RPC calls")
        .register(registry);

    Gauge.builder("rpc.requests.served.total", metricProvider("TotalRequests"))
        .tags(baseTags)
        .description("Total num of requests served by the RPC server")
        .register(registry);

    Gauge.builder("rpc.connections.open", metricProvider("NumOpenConnections"))
        .tags(baseTags)
        .description("Current number of open RPC connections")
        .register(registry);

    Gauge.builder("rpc.call.queue.size", metricProvider("CallQueueLength"))
        .tags(baseTags)
        .description("Current length of the RPC call queue")
        .register(registry);

    Gauge.builder("rpc.call.authentication.success.total", metricProvider("RpcAuthenticationSuccesses"))
        .tags(baseTags)
        .description("Total number of RPC authentication successes")
        .register(registry);

    Gauge.builder("rpc.call.authentication.failure.total", metricProvider("RpcAuthenticationFailures"))
        .tags(baseTags)
        .description("Total number of RPC authentication failures")
        .register(registry);
  }

  @Override
  public void putMetrics(MetricsRecord record) {
    if (record.name().equals(RPC_RECORD_NAME)) {
      record.metrics().forEach(metric ->
          metricsContainer.put(metric.name(), metric.value().doubleValue()));
    }
  }

  @Override
  public void flush() {

  }

  @Override
  public void init(SubsetConfiguration conf) {

  }

  private Supplier<Number> metricProvider(String name) {
    return () -> metricsContainer.getOrDefault(name, 0.0);
  }
}
