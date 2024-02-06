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

import org.apache.hadoop.hdfs.DFSClient;
import org.apache.hadoop.hdfs.protocol.DirectoryListing;
import org.apache.hadoop.hdfs.protocol.HdfsFileStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.conf.SmartConf;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.hdfs.CompatibilityHelperLoader;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metastore.ingestion.FileStatusIngester;
import org.smartdata.metastore.ingestion.IngestionTask;
import org.smartdata.model.ErasureCodingPolicyInfo;
import org.smartdata.model.FileInfo;
import org.smartdata.model.FileInfoBatch;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import org.smartdata.model.PathChecker;

import static org.smartdata.hdfs.CompatibilityHelperLoader.getHelper;

public class NamespaceFetcher {
  private final ScheduledExecutorService scheduledExecutorService;
  private final long fetchInterval;
  private ScheduledFuture[] fetchTaskFutures;
  private ScheduledFuture[] consumerFutures;
  private FileStatusIngester[] consumers;
  private IngestionTask[] ingestionTasks;
  private DFSClient client;
  private MetaStore metaStore;
  private SmartConf conf;

  public static final Logger LOG = LoggerFactory.getLogger(NamespaceFetcher.class);

  public NamespaceFetcher(DFSClient client, MetaStore metaStore, SmartConf conf) {
    this(client, metaStore, null, conf);
  }

  public NamespaceFetcher(DFSClient client, MetaStore metaStore,
                          ScheduledExecutorService service, SmartConf conf) {
    int numProducers = conf.getInt(SmartConfKeys.SMART_NAMESPACE_FETCHER_PRODUCERS_NUM_KEY,
        SmartConfKeys.SMART_NAMESPACE_FETCHER_PRODUCERS_NUM_DEFAULT);
    numProducers = numProducers <= 0 ? 1 : numProducers;
    this.ingestionTasks = new IngestionTask[numProducers];
    HdfsFetchTask.init();
    for (int i = 0; i < numProducers; i++) {
      ingestionTasks[i] = new HdfsFetchTask(ingestionTasks, client, conf);
    }

    int numConsumers = conf.getInt(SmartConfKeys.SMART_NAMESPACE_FETCHER_CONSUMERS_NUM_KEY,
        SmartConfKeys.SMART_NAMESPACE_FETCHER_CONSUMERS_NUM_DEFAULT);
    numConsumers = numConsumers <= 0 ? 1 : numConsumers;
    consumers = new FileStatusIngester[numConsumers];
    for (int i = 0; i < numConsumers; i++) {
      consumers[i] = new FileStatusIngester(metaStore);
    }
    this.fetchInterval = conf.getLong(
        SmartConfKeys.SMART_NAMESPACE_FETCH_INTERVAL_MS_KEY,
        SmartConfKeys.SMART_NAMESPACE_FETCH_INTERVAL_MS_DEFAULT
    );
    if (service != null) {
      this.scheduledExecutorService = service;
    } else {
      scheduledExecutorService = Executors.newScheduledThreadPool(numProducers + numConsumers);
    }
    this.client = client;
    this.metaStore = metaStore;
    this.conf = conf;
  }

  public static void init(SmartConf conf) {
    IngestionTask.init(conf);
  }

  public void startFetch() throws IOException {
    try {
      init(conf);
      metaStore.deleteAllEcPolicies();
      Map<Byte, String> idToPolicyName =
          CompatibilityHelperLoader.getHelper().getErasureCodingPolicies(client);
      if (idToPolicyName != null) {
        ArrayList<ErasureCodingPolicyInfo> ecInfos = new ArrayList<>();
        for (Byte id : idToPolicyName.keySet()) {
          ecInfos.add(new ErasureCodingPolicyInfo(id, idToPolicyName.get(id)));
        }
        metaStore.insertEcPolicies(ecInfos);
        LOG.info("Finished fetching all EC policies!");
      }
    } catch (MetaStoreException e) {
      throw new IOException("Failed to clean and fetch EC policies!", e);
    }

    try {
      metaStore.deleteAllFileInfo();
    } catch (MetaStoreException e) {
      throw new IOException("Error while reset files", e);
    }
    this.fetchTaskFutures = new ScheduledFuture[ingestionTasks.length];
    for (int i = 0; i < ingestionTasks.length; i++) {
      fetchTaskFutures[i] = this.scheduledExecutorService.scheduleAtFixedRate(
          ingestionTasks[i], 0, fetchInterval, TimeUnit.MILLISECONDS);
    }

    this.consumerFutures = new ScheduledFuture[consumers.length];
    for (int i = 0; i < consumers.length; i++) {
      consumerFutures[i] = this.scheduledExecutorService.scheduleAtFixedRate(
          consumers[i], 0, fetchInterval, TimeUnit.MILLISECONDS);
    }
    LOG.info("Started.");
  }

  public static void init(String dir) {
    IngestionTask.init(dir);
  }

  /*
  startFetch(dir) is used to restart fetcher to fetch one specific dir.
  In rename event, when src is not in file table because it is not fetched or other reason,
  dest should be fetched by using startFetch(dest).
  */
  public void startFetch(String dir) {
    init(dir);
    this.fetchTaskFutures = new ScheduledFuture[ingestionTasks.length];
    for (int i = 0; i < ingestionTasks.length; i++) {
      fetchTaskFutures[i] = this.scheduledExecutorService.scheduleAtFixedRate(
          ingestionTasks[i], 0, fetchInterval, TimeUnit.MILLISECONDS);
    }

    this.consumerFutures = new ScheduledFuture[consumers.length];
    for (int i = 0; i < consumers.length; i++) {
      consumerFutures[i] = this.scheduledExecutorService.scheduleAtFixedRate(
          consumers[i], 0, fetchInterval, TimeUnit.MILLISECONDS);
    }
    LOG.info("Start fetch the given dir.");
  }

  public boolean fetchFinished() {
    return IngestionTask.finished();
  }

  public void stop() {
    if (fetchTaskFutures != null) {
      for (ScheduledFuture f : fetchTaskFutures) {
        if (f != null) {
          f.cancel(true);
        }
      }
    }
    if (consumerFutures != null) {
      for (ScheduledFuture f : consumerFutures) {
        if (f != null) {
          f.cancel(true);
        }
      }
    }
  }

  private static class HdfsFetchTask extends IngestionTask {
    private final HdfsFileStatus[] EMPTY_STATUS = new HdfsFileStatus[0];
    private final DFSClient client;
    private byte[] startAfter = null;
    private final byte[] empty = HdfsFileStatus.EMPTY_NAME;
    private String parent = "";
    private String pendingParent;
    private IngestionTask[] ingestionTasks;
    private static int idCounter = 0;
    private int id;

    private final PathChecker pathChecker;

    public HdfsFetchTask(IngestionTask[] ingestionTasks, DFSClient client, SmartConf conf) {
      super();
      id = idCounter++;
      this.ingestionTasks = ingestionTasks;
      this.client = client;
      defaultBatchSize = conf.getInt(SmartConfKeys
              .SMART_NAMESPACE_FETCHER_BATCH_KEY,
          SmartConfKeys.SMART_NAMESPACE_FETCHER_BATCH_DEFAULT);
      this.pathChecker = new PathChecker(conf);
    }

    public static void init() {
      HdfsFetchTask.idCounter = 0;
    }

    // BFS finished
    public boolean isDequeEmpty() {
      for (IngestionTask ingestionTask : ingestionTasks) {
        if (((HdfsFetchTask) ingestionTask).parent != null) {
          return false;
        }
      }
      return true;
    }

    @Override
    public void run() {
      if (LOG.isDebugEnabled()) {
        long curr = System.currentTimeMillis();
        if (curr - lastUpdateTime >= 2000) {
          LOG.debug(String.format(
              "%d sec, numDirectories = %d, numFiles = %d, batchsInqueue = %d",
              (curr - startTime) / 1000,
              numDirectoriesFetched.get(), numFilesFetched.get(), batches.size()));
          lastUpdateTime = curr;
        }
      }

      if (batches.size() >= maxPendingBatches) {
        return;
      }

      if (this.pendingParent != null) {
        this.parent = pendingParent;
        this.pendingParent = null;
      } else {
        this.parent = deque.pollFirst();
      }
      if (parent == null) {
        if (currentBatch.actualSize() > 0) {
          try {
            this.batches.put(currentBatch);
          } catch (InterruptedException e) {
            LOG.error("Current batch actual size = "
                + currentBatch.actualSize(), e);
          }
          this.currentBatch = new FileInfoBatch(defaultBatchSize);
        }

        if (this.id == 0 && isDequeEmpty() && this.batches.isEmpty()) {
          if (!IngestionTask.isFinished) {
            IngestionTask.isFinished = true;
            long curr = System.currentTimeMillis();
            LOG.info(String.format(
                "Finished fetch Namespace! %ds, %dms used, numDirs = %d, numFiles = %d",
                (curr - startTime) / 1000, (curr - startTime) % 1000,
                numDirectoriesFetched.get(), numFilesFetched.get()));
          }
        }
        return;
      }

      if (startAfter == null) {
        String tmpParent = parent.endsWith("/") ? parent : parent + "/";

        if (pathChecker.isIgnored(tmpParent)) {
          return;
        }
      }

      try {
        HdfsFileStatus status = client.getFileInfo(parent);

        if (status == null) {
          throw new IOException();
        }

        if (!status.isDir()) {
          this.addFileStatus(convertToFileInfo(status, parent));
          numFilesFetched.incrementAndGet();
        }

        if (status.isDir()) {
          if (startAfter == null) {
            FileInfo internal = convertToFileInfo(status, "");
            internal.setPath(parent);
            this.addFileStatus(internal);
            numDirectoriesFetched.incrementAndGet();
          }

          HdfsFileStatus[] children;
          do {
            children = listStatus(parent);
            if (children == null || children.length == 0) {
              break;
            }
            for (HdfsFileStatus child : children) {
              String fullName = child.getFullName(parent);
              if (pathChecker.isIgnored(fullName)) {
                continue;
              }
              if (child.isDir()) {
                this.deque.add(fullName);
              } else {
                this.addFileStatus(convertToFileInfo(child, parent));
                numFilesFetched.incrementAndGet();
              }
            }
          } while (startAfter != null && batches.size() < maxPendingBatches);
          if (startAfter != null) {
            pendingParent = parent;
          }
        }
      } catch (IOException | InterruptedException e) {
        startAfter = null;
        LOG.error("Totally, numDirectoriesFetched = " + numDirectoriesFetched
            + ", numFilesFetched = " + numFilesFetched
            + ". Parent = " + parent, e);
      }

    }

    /**
     *  Code copy form {@link org.apache.hadoop.fs.Hdfs}
     */
    private HdfsFileStatus[] listStatus(String src) throws IOException {
      DirectoryListing thisListing = client.listPaths(
          src, startAfter == null ? empty : startAfter);
      if (thisListing == null) {
        // the directory does not exist
        startAfter = null;
        return EMPTY_STATUS;
      }
      HdfsFileStatus[] partialListing = thisListing.getPartialListing();
      if (!thisListing.hasMore()) {
        // got all entries of the directory
        startAfter = null;
      } else {
        startAfter = thisListing.getLastName();
      }
      return partialListing;
    }

    private FileInfo convertToFileInfo(HdfsFileStatus status, String parent) {
      FileInfo fileInfo = new FileInfo(
          status.getFullName(parent),
          status.getFileId(),
          status.getLen(),
          status.isDir(),
          status.getReplication(),
          status.getBlockSize(),
          status.getModificationTime(),
          status.getAccessTime(),
          status.getPermission().toShort(),
          status.getOwner(),
          status.getGroup(),
          status.getStoragePolicy(),
          getHelper().getErasureCodingPolicy(status));
      return fileInfo;
    }
  }
}
