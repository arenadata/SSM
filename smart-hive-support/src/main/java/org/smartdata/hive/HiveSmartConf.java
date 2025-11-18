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
package org.smartdata.hive;

import org.apache.hadoop.conf.Configuration;
import org.smartdata.retry.RetryStrategy;

public class HiveSmartConf extends Configuration {
  private static final String HIVE_CONFIG_FILE = "hive-site.xml";

  public static final String EVENT_APPLIER_RETRY_STRATEGY = "smart.hive.event.applier.retry.strategy";
  public static final RetryStrategy EVENT_APPLIER_RETRY_STRATEGY_DEFAULT = RetryStrategy.FIXED_SLEEP;

  public static final String EVENT_APPLIER_RETRY_INTERVAL_MS = "smart.hive.event.applier.retry.interval.ms";
  public static final long EVENT_APPLIER_RETRY_INTERVAL_MS_DEFAULT = 1000L;

  public static final String EVENT_APPLIER_MAX_RETRIES = "smart.hive.event.applier.retry.max";
  public static final int EVENT_APPLIER_MAX_RETRIES_DEFAULT = 10;

  public static final String HMS_FETCH_PERIOD_MS = "smart.hive.event.fetch.period.ms";
  public static final long HMS_FETCH_PERIOD_MS_DEFAULT = 10000L;

  public static final String HMS_FETCH_BATCH_SIZE = "smart.hive.event.fetch.batch.size";
  public static final int HMS_FETCH_BATCH_SIZE_DEFAULT = 8192;

  public static final String HMS_SNAPSHOT_THREADS_COUNT = "smart.hive.event.snapshot.threads.count";
  public static final int HMS_SNAPSHOT_THREADS_COUNT_DEFAULT = 16;

  public static final String HMS_FULL_SYNC = "smart.hive.event.sync.full";
  public static final boolean HMS_FULL_SYNC_DEFAULT = false;

  public static final String HMS_CLIENT_CACHE_TTL_MS = "smart.hive.client.cache.ttl.ms";
  public static final long HMS_CLIENT_CACHE_TTL_MS_DEFAULT = 120000L;

  public static final String HMS_CLIENT_CACHE_MAX_CAPACITY = "smart.hive.client.cache.size.max";
  public static final int HMS_CLIENT_CACHE_MAX_CAPACITY_DEFAULT = 50;

  public static final String HMS_SYNC_PROGRESS_FLUSH_INTERVAL_MS =
      "smart.hive.sync.progress.flush.interval.ms";
  public static final long HMS_SYNC_PROGRESS_FLUSH_INTERVAL_MS_DEFAULT = 5000;

  public HiveSmartConf(Configuration conf) {
    super(conf);

    addResource(HIVE_CONFIG_FILE);
    loadSystemProperties();
  }

  public long getFetchPeriodMs() {
    return getLong(HMS_FETCH_PERIOD_MS, HMS_FETCH_PERIOD_MS_DEFAULT);
  }

  public int getFetchBatchSize() {
    return getInt(HMS_FETCH_BATCH_SIZE, HMS_FETCH_BATCH_SIZE_DEFAULT);
  }

  public boolean isFullMetastoreSync() {
    return getBoolean(HMS_FULL_SYNC, HMS_FULL_SYNC_DEFAULT);
  }

  public RetryStrategy getEventApplierRetryStrategy() {
    return getEnum(EVENT_APPLIER_RETRY_STRATEGY, EVENT_APPLIER_RETRY_STRATEGY_DEFAULT);
  }

  public long getEventApplierRetryIntervalMs() {
    return getLong(EVENT_APPLIER_RETRY_INTERVAL_MS, EVENT_APPLIER_RETRY_INTERVAL_MS_DEFAULT);
  }

  public int getEventApplierMaxRetries() {
    return getInt(EVENT_APPLIER_MAX_RETRIES, EVENT_APPLIER_MAX_RETRIES_DEFAULT);
  }

  public int getSnapshotFetcherThreadsCount() {
    return getInt(HMS_SNAPSHOT_THREADS_COUNT, HMS_SNAPSHOT_THREADS_COUNT_DEFAULT);
  }

  private void loadSystemProperties() {
    for (String propertyName : getProps().stringPropertyNames()) {
      String systemPropertyValue = System.getProperty(propertyName);
      if (systemPropertyValue != null) {
        set(propertyName, systemPropertyValue);
      }
    }
  }
}
