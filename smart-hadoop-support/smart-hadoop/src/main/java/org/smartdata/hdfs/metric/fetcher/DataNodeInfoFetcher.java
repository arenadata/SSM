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
package org.smartdata.hdfs.metric.fetcher;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hdfs.DFSClient;
import org.apache.hadoop.hdfs.protocol.HdfsConstants;
import org.apache.hadoop.hdfs.server.protocol.DatanodeStorageReport;
import org.apache.hadoop.hdfs.server.protocol.StorageReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.model.StorageCapacity;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Fetch and maintain data nodes related info.
 */
public class DataNodeInfoFetcher {
  private final long updateInterval;
  private final DFSClient client;
  private final MetaStore metaStore;
  private final ScheduledExecutorService scheduledExecutorService;
  private ScheduledFuture<?> dnStorageReportProcTaskFuture;
  private DataNodeInfoFetchTask procTask;
  public static final Logger LOG =
      LoggerFactory.getLogger(DataNodeInfoFetcher.class);

  public DataNodeInfoFetcher(DFSClient client, MetaStore metaStore,
                             ScheduledExecutorService service, Configuration conf) {
    this.client = client;
    this.metaStore = metaStore;
    this.scheduledExecutorService = service;
    updateInterval = conf.getInt(
        SmartConfKeys.SMART_STORAGE_INFO_UPDATE_INTERVAL_KEY,
        SmartConfKeys.SMART_STORAGE_INFO_UPDATE_INTERVAL_DEFAULT) * 1000L;
  }

  public void start() throws IOException {
    LOG.info("Starting DataNodeInfoFetcher service ...");

    procTask = new DataNodeInfoFetchTask(client, metaStore);
    dnStorageReportProcTaskFuture = scheduledExecutorService.scheduleAtFixedRate(
        procTask, 0, updateInterval, TimeUnit.MILLISECONDS);

    LOG.info("DataNodeInfoFetcher service started.");
  }

  public boolean isFetchFinished() {
    return this.procTask.isFinished();
  }

  public void stop() {
    if (dnStorageReportProcTaskFuture != null) {
      dnStorageReportProcTaskFuture.cancel(false);
    }
  }

  private static class DataNodeInfoFetchTask implements Runnable {
    private final DFSClient client;
    private final MetaStore metaStore;
    private volatile boolean isFinished = false;
    private Map<String, StorageCapacity> storages;
    public final Logger LOG =
        LoggerFactory.getLogger(DataNodeInfoFetchTask.class);

    public DataNodeInfoFetchTask(DFSClient client, MetaStore metaStore)
        throws IOException {
      this.client = client;
      this.metaStore = metaStore;

      try {
        storages = metaStore.getStorageCapacity();
      } catch (MetaStoreException e) {
        throw new IOException("Can not get storage info");
      }
    }

    @Override
    public void run() {
      StorageCapacity sc;
      Map<String, StorageCapacity> storagesNow = new HashMap<>();
      try {
        final DatanodeStorageReport[] reports =
            client.getDatanodeStorageReport(HdfsConstants.DatanodeReportType.LIVE);
        for (DatanodeStorageReport r : reports) {
          //insert record in DataNodeStorageInfoTable
          for (int i = 0; i < r.getStorageReports().length; i++) {
            StorageReport storageReport = r.getStorageReports()[i];
            long capacity = storageReport.getCapacity();
            long remaining = storageReport.getRemaining();

            String sn = storageReport.getStorage().getStorageType().name();
            if (!storagesNow.containsKey(sn)) {
              sc = new StorageCapacity(sn, capacity, remaining);
              storagesNow.put(sn, sc);
            } else {
              sc = storagesNow.get(sn);
              sc.addCapacity(capacity);
              sc.addFree(remaining);
            }
          }
        }
        updateStorages(storagesNow);
        storages = storagesNow;
        isFinished = true;
      } catch (IOException e) {
        LOG.error("Process datanode report error", e);
      }
    }

    private void updateStorages(Map<String, StorageCapacity> storagesNow)
        throws MetaStoreException {
      String k;
      StorageCapacity v;
      List<StorageCapacity> sc = new ArrayList<>();
      for (Entry<String, StorageCapacity> kv : storages.entrySet()) {
        k = kv.getKey();
        if (storagesNow.containsKey(k)) {
          v = storagesNow.get(k);
          if (!kv.getValue().equals(v)) {
            sc.add(v);
          }
        } else {
          metaStore.deleteStorage(kv.getKey());
        }
      }

      for (Entry<String, StorageCapacity> kv : storagesNow.entrySet()) {
        if (!storages.containsKey(kv.getKey())) {
          sc.add(kv.getValue());
        }
      }
      metaStore.insertUpdateStoragesTable(sc);
    }

    public boolean isFinished() {
      return this.isFinished;
    }
  }
}
