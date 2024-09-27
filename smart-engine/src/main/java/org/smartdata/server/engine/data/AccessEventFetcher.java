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
package org.smartdata.server.engine.data;

import io.micrometer.core.instrument.Counter;
import org.apache.hadoop.conf.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.metastore.accesscount.AccessEventAggregator;
import org.smartdata.metrics.FileAccessEvent;
import org.smartdata.metrics.FileAccessEventCollector;
import org.smartdata.metrics.MetricsFactory;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static org.smartdata.conf.SmartConfKeys.SMART_ACCESS_EVENT_FETCH_INTERVAL_MS_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_ACCESS_EVENT_FETCH_INTERVAL_MS_KEY;

public class AccessEventFetcher {
  static final Logger LOG = LoggerFactory.getLogger(AccessEventFetcher.class);

  private final ScheduledExecutorService scheduledExecutorService;
  private final Long fetchInterval;
  private final FetchTask fetchTask;
  private ScheduledFuture<?> scheduledFuture;

  public AccessEventFetcher(
      Configuration conf,
      AccessEventAggregator accessEventAggregator,
      ScheduledExecutorService service,
      FileAccessEventCollector collector,
      MetricsFactory metricsFactory) {
    this.fetchInterval = conf.getLong(
        SMART_ACCESS_EVENT_FETCH_INTERVAL_MS_KEY,
        SMART_ACCESS_EVENT_FETCH_INTERVAL_MS_DEFAULT
    );
    Counter eventsCounter = metricsFactory.counter("access-events-count");
    this.fetchTask = new FetchTask(accessEventAggregator, collector, eventsCounter);
    this.scheduledExecutorService = service;
  }

  public void start() {
    this.scheduledFuture = scheduledExecutorService.scheduleAtFixedRate(
        fetchTask, 0, fetchInterval, TimeUnit.MILLISECONDS);
  }

  public void stop() {
    if (scheduledFuture != null) {
      scheduledFuture.cancel(true);
    }
  }

  private static class FetchTask implements Runnable {
    private final AccessEventAggregator accessEventAggregator;
    private final FileAccessEventCollector collector;
    private final Counter eventsCounter;

    public FetchTask(AccessEventAggregator accessEventAggregator,
                     FileAccessEventCollector collector, Counter eventsCounter) {
      this.accessEventAggregator = accessEventAggregator;
      this.collector = collector;
      this.eventsCounter = eventsCounter;
    }

    @Override
    public void run() {
      try {
        List<FileAccessEvent> events = this.collector.collect();
        if (!events.isEmpty()) {
          eventsCounter.increment(events.size());
          accessEventAggregator.aggregate(events);
        }
      } catch (IOException e) {
        LOG.error("IngestionTask onAccessEventsArrived error", e);
      }
    }
  }
}
