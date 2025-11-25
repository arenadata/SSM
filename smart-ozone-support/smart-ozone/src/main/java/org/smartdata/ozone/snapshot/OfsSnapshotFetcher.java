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
package org.smartdata.ozone.snapshot;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.protocol.ErasureCodingPolicy;
import org.apache.hadoop.hdfs.protocol.HdfsFileStatus;
import org.smartdata.ozone.model.FsObjectStreamRecord;
import org.smartdata.ozone.model.OzoneFileInfo;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.function.Supplier;

@Slf4j
public class OfsSnapshotFetcher implements AutoCloseable {
  private final static String SNAPSHOT_PREFIX = "ssm_";
  private final static String ROOT_DIR = "/";
  private final static byte DEFAULT_EC_POLICY_ID = 0;

  private final FileSystem fs;
  private final ExecutorService executor;
  private final Supplier<Long> currentTimeMsSupplier;

  @Getter
  private final BlockingQueue<FsObjectStreamRecord> outputQueue;
  @Getter
  private final Map<Path, String> bucketSnapshots;

  private final AtomicBoolean isClosed;
  private final AtomicBoolean pollStarted;

  public OfsSnapshotFetcher(
      FileSystem fs,
      ExecutorService executor,
      int batchSize) {
    this(fs, executor, System::currentTimeMillis, batchSize);
  }

  public OfsSnapshotFetcher(
      FileSystem fs,
      ExecutorService executor,
      Supplier<Long> currentTimeMsSupplier,
      int batchSize) {
    this.fs = fs;
    this.executor = executor;
    this.currentTimeMsSupplier = currentTimeMsSupplier;
    this.outputQueue = new ArrayBlockingQueue<>(batchSize);
    this.bucketSnapshots = new ConcurrentHashMap<>();
    this.pollStarted = new AtomicBoolean(false);
    this.isClosed = new AtomicBoolean(false);
  }

  public BlockingQueue<FsObjectStreamRecord> runSnapshot() {
    if (pollStarted.compareAndSet(false, true)) {
      runSnapshotAsync();
    }
    return outputQueue;
  }

  CompletableFuture<Void> runSnapshotAsync() {
    return pollVolumes()
        .thenRun(() -> send(FsObjectStreamRecord.endOfStreamRecord()))
        .thenRun(() -> log.info("Hive metastore snapshot is successfully done"))
        .exceptionally(error -> {
          handleError(error);
          return null;
        });
  }

  private CompletableFuture<Void> pollVolumes() {
    return supplyAsync(() -> listStatuses(new Path(ROOT_DIR)))
        .thenComposeAsync(statuses ->
                executeInParallel(statuses, this::handleVolume),
            executor);
  }

  private CompletableFuture<Void> handleVolume(FileStatus fileStatus) {
    saveFile(fileStatus, OzoneFileInfo.builder().isVolume(true));
    return executeInParallel(
        listStatuses(fileStatus.getPath()),
        this::handleBucket);
  }

  private CompletableFuture<Void> handleBucket(FileStatus fileStatus) {
    saveFile(fileStatus, OzoneFileInfo.builder().isBucket(true));

    return createBucketSnapshot(fileStatus)
        // list keys in the snapshot dir
        .thenApplyAsync(this::listStatuses, executor)
        .thenComposeAsync(statuses ->
                executeInParallel(statuses, this::handleKey),
            executor);
  }

  private CompletableFuture<Void> handleKey(FileStatus fileStatus) {
    saveFile(fileStatus, OzoneFileInfo.builder());

    if (!fileStatus.isDirectory()) {
      return CompletableFuture.completedFuture(null);
    }

    return executeInParallel(
        listStatuses(fileStatus.getPath()),
        this::handleKey);
  }

  private CompletableFuture<Path> createBucketSnapshot(FileStatus fileStatus) {
    String snapshotName = SNAPSHOT_PREFIX
        + fileStatus.getPath().getName()
        + "_"
        + currentTimeMsSupplier.get();
    return supplyAsync(() -> fs.createSnapshot(fileStatus.getPath(), snapshotName))
        .thenApplyAsync(snapshotPath -> {
          bucketSnapshots.put(fileStatus.getPath(), snapshotName);
          return snapshotPath;
        }, executor);
  }

  private void saveFile(FileStatus fileStatus, OzoneFileInfo.Builder fileBuilder) {
    OzoneFileInfo fileInfo = toFileInfo(fileBuilder, (HdfsFileStatus) fileStatus);
    send(fileInfo);
  }

  private OzoneFileInfo toFileInfo(OzoneFileInfo.Builder fileBuilder, HdfsFileStatus status) {
    byte erasureCodingPolicy = Optional.ofNullable(status.getErasureCodingPolicy())
        .map(ErasureCodingPolicy::getId)
        .orElse(DEFAULT_EC_POLICY_ID);

    return fileBuilder
        .path(status.getPath().toString())
        .length(status.getLen())
        .blockReplication(status.getReplication())
        .blockSize(status.getBlockSize())
        .modificationTime(status.getModificationTime())
        .accessTime(status.getAccessTime())
        .storagePolicy(status.getStoragePolicy())
        .owner(status.getOwner())
        .group(status.getGroup())
        .permission(status.getPermission().toShort())
        .erasureCodingPolicy(erasureCodingPolicy)
        .build();
  }

  private void send(FsObjectStreamRecord fileInfo) {
    try {
      outputQueue.put(fileInfo);
    } catch (InterruptedException e) {
      log.error("Failed to send file info {}", fileInfo, e);
      throw new RuntimeException(e);
    }
  }

  private List<FileStatus> listStatuses(Path path) {
    try {
      return Arrays.asList(fs.listStatus(path));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private <V> CompletableFuture<V> supplyAsync(Callable<V> supplier) {
    return CompletableFuture.supplyAsync(() -> {
      try {
        return supplier.call();
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }, executor);
  }

  private <T> CompletableFuture<Void> executeInParallel(
      Collection<T> entities,
      Function<T, CompletableFuture<?>> transformer) {
    throwIfClosed();
    return CompletableFuture.allOf(
        entities
            .stream()
            .map(transformer::apply)
            .toArray(CompletableFuture[]::new)
    );
  }

  private void throwIfClosed() {
    if (isClosed.get()) {
      throw new CancellationException("HmsEventSource is closed");
    }
  }

  @Override
  public void close() {
    executor.shutdown();
    isClosed.set(true);
    outputQueue.add(FsObjectStreamRecord.endOfStreamRecord());
  }

  private void handleError(Throwable exception) {
    log.error("Error polling file statuses from Ozone", exception);
    close();
  }

}
