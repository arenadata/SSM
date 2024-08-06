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
package org.smartdata.server.engine.cmdlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.conf.SmartConf;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.utils.StringUtil;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Deletes terminated cmdlets from metastore, that are older than the configured lifetime,
 * or if their number exceeds the specified threshold.
 */
public class DeleteTerminatedCmdletsTask implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(DeleteTerminatedCmdletsTask.class);

  private static final long CMDLET_LIFETIME_MIN_VALUE_MS = 5000;
  private static final int CMDLET_LIFETIME_CHECKS_PER_INTERVAL = 20;

  private final MetaStore metaStore;
  private final AtomicLong numCmdletsFinished;

  private final int maxRecordsCount;
  private final long maxRecordLifetime;
  private final long lifetimeCheckInterval;
  private long lastPurgeTimestamp;

  public DeleteTerminatedCmdletsTask(SmartConf conf, MetaStore metaStore) {
    this.metaStore = metaStore;
    this.numCmdletsFinished = new AtomicLong(0);
    this.lastPurgeTimestamp = System.currentTimeMillis();
    this.maxRecordsCount = conf.getInt(
        SmartConfKeys.SMART_CMDLET_HIST_MAX_NUM_RECORDS_KEY,
        SmartConfKeys.SMART_CMDLET_HIST_MAX_NUM_RECORDS_DEFAULT);

    String rawMaxRecordLifetime = conf.get(
        SmartConfKeys.SMART_CMDLET_HIST_MAX_RECORD_LIFETIME_KEY,
        SmartConfKeys.SMART_CMDLET_HIST_MAX_RECORD_LIFETIME_DEFAULT);
    this.maxRecordLifetime = StringUtil.parseTimeString(rawMaxRecordLifetime);

    this.lifetimeCheckInterval = Math.max(
        maxRecordLifetime / CMDLET_LIFETIME_CHECKS_PER_INTERVAL,
        CMDLET_LIFETIME_MIN_VALUE_MS);
  }

  public void init() throws MetaStoreException {
    numCmdletsFinished.addAndGet(metaStore.getNumCmdletsInTerminatedStates());
  }

  @Override
  public void run() {
    try {
      long now = System.currentTimeMillis();
      if (now - lastPurgeTimestamp >= lifetimeCheckInterval) {
        int cmdletsDeleted = metaStore
            .deleteFinishedCmdletsWithGenTimeBefore(now - maxRecordLifetime);
        numCmdletsFinished.getAndAdd(-cmdletsDeleted);
        lastPurgeTimestamp = now;
      }

      if (numCmdletsFinished.get() > maxRecordsCount) {
        int cmdletsDeleted = metaStore.deleteKeepNewCmdlets(maxRecordsCount);
        numCmdletsFinished.getAndAdd(-cmdletsDeleted);
      }
    } catch (MetaStoreException e) {
      LOG.error("Exception when purging cmdlets.", e);
    }
  }

  public void onCmdletFinished() {
    numCmdletsFinished.incrementAndGet();
  }
}
