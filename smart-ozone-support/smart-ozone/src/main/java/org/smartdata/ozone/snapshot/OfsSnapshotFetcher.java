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
import org.apache.hadoop.hdds.client.ECReplicationConfig;
import org.apache.hadoop.hdds.client.ReplicatedReplicationConfig;
import org.apache.hadoop.hdds.client.ReplicationConfig;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.apache.hadoop.ozone.OFSPath;
import org.apache.hadoop.ozone.client.ObjectStore;
import org.apache.hadoop.ozone.client.OzoneBucket;
import org.apache.hadoop.ozone.client.OzoneKeyDetails;
import org.apache.hadoop.ozone.client.OzoneVolume;
import org.smartdata.ozone.model.FsObjectStreamRecord;
import org.smartdata.ozone.model.OzoneFileInfo;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Spliterators;
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
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

@Slf4j
public class OfsSnapshotFetcher implements AutoCloseable {
  private final static String SNAPSHOT_PREFIX = "ssm-";
  private final static String ROOT_DIR = "/";
  private final static char PATH_DELIMITER = '/';
  private final static short DEFAULT_BLOCK_REPLICATION = 0;

  private final FileSystem fs;
  private final OzoneConfiguration conf;
  private final ObjectStore objectStore;
  private final ExecutorService executor;
  private final Supplier<Long> currentTimeMsSupplier;

  @Getter
  private final BlockingQueue<FsObjectStreamRecord> outputQueue;
  @Getter
  private final Map<Path, String> bucketSnapshots;

  private final AtomicBoolean isClosed;
  private final AtomicBoolean pollStarted;

  @lombok.Builder
  public OfsSnapshotFetcher(
      FileSystem fs,
      ObjectStore objectStore,
      OzoneConfiguration conf,
      ExecutorService executor,
      int batchSize) {
    this(fs, objectStore, conf, executor, System::currentTimeMillis, batchSize);
  }

  public OfsSnapshotFetcher(
      FileSystem fs,
      ObjectStore objectStore,
      OzoneConfiguration conf,
      ExecutorService executor,
      Supplier<Long> currentTimeMsSupplier,
      int batchSize) {
    this.fs = fs;
    this.executor = executor;
    this.objectStore = objectStore;
    this.conf = conf;
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

  @Override
  public void close() {
    if (executor != null) {
      executor.shutdown();
    }

    isClosed.set(true);
    outputQueue.add(FsObjectStreamRecord.endOfStreamRecord());
  }

  CompletableFuture<Void> runSnapshotAsync() {
    return pollVolumes()
        .thenRun(() -> send(FsObjectStreamRecord.endOfStreamRecord()))
        .thenRun(() -> log.info("Ozone snapshot is successfully done"))
        .exceptionally(error -> {
          handleError(error);
          return null;
        });
  }

  private CompletableFuture<Void> pollVolumes() {
    return supplyAsync(() -> objectStore.listVolumes(null))
        .thenComposeAsync(statuses ->
                executeInParallel(statuses, this::handleVolume),
            executor);
  }

  private CompletableFuture<Void> handleVolume(OzoneVolume volume) {
    try {
      FileStatus fileStatus = fs.getFileStatus(new Path(ROOT_DIR, volume.getName()));
      return handleVolume(fileStatus);
    } catch (IOException e) {
      throw new RuntimeException("Error handling volume", e);
    }
  }

  private CompletableFuture<Void> handleVolume(FileStatus fileStatus) {
    OzoneFileInfo.Builder fileBuilder = OzoneFileInfo.builder()
        .path(pathWithoutAuthority(fileStatus.getPath()))
        .isVolume(true);
    return saveFile(fileStatus, fileBuilder)
        .thenComposeAsync(ignore -> executeInParallel(
            listStatuses(fileStatus.getPath()),
            this::handleBucket), executor);
  }

  private CompletableFuture<Void> handleBucket(FileStatus fileStatus) {
    OzoneFileInfo.Builder fileBuilder = OzoneFileInfo.builder()
        .path(pathWithoutAuthority(fileStatus.getPath()))
        .isBucket(true);
    return saveFile(fileStatus, fileBuilder)
        .thenComposeAsync(ignore -> createBucketSnapshot(fileStatus), executor)
        // list keys in the snapshot dir
        .thenApplyAsync(this::listStatuses, executor)
        .thenComposeAsync(statuses ->
                executeInParallel(statuses, this::handleKey),
            executor);
  }

  private CompletableFuture<Void> handleKey(FileStatus fileStatus) {
    Path filePath = getOriginalFilePath(fileStatus.getPath());
    OzoneFileInfo.Builder fileBuilder = OzoneFileInfo.builder()
        .path(pathWithoutAuthority(filePath));
    return saveFile(fileStatus, fileBuilder)
        .thenComposeAsync(ignore -> handleChildrenIfDirectory(fileStatus), executor);
  }

  private CompletableFuture<Void> handleChildrenIfDirectory(FileStatus fileStatus) {
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
        + "-"
        + currentTimeMsSupplier.get();
    return supplyAsync(() -> fs.createSnapshot(fileStatus.getPath(), snapshotName))
        .thenApplyAsync(snapshotPath -> {
          bucketSnapshots.put(fileStatus.getPath(), snapshotName);
          return snapshotPath;
        }, executor);
  }

  private CompletableFuture<Void> saveFile(FileStatus fileStatus, OzoneFileInfo.Builder fileBuilder) {
    return toEnrichedFileInfo(fileBuilder, fileStatus)
        .thenAcceptAsync(this::send, executor);
  }

  private CompletableFuture<OzoneFileInfo> toEnrichedFileInfo(OzoneFileInfo.Builder fileBuilder, FileStatus status) {
    return enrichedBuilder(fileBuilder, status)
        .thenApply(builder -> toFileInfo(builder, status));
  }

  private OzoneFileInfo toFileInfo(OzoneFileInfo.Builder fileBuilder, FileStatus status) {
    return fileBuilder
        .length(status.getLen())
        .blockReplication(status.getReplication())
        .blockSize(status.getBlockSize())
        .modificationTime(status.getModificationTime())
        .accessTime(status.getAccessTime())
        .owner(status.getOwner())
        .group(status.getGroup())
        .permission(status.getPermission().toShort())
        .build();
  }

  private CompletableFuture<OzoneFileInfo.Builder> enrichedBuilder(
      OzoneFileInfo.Builder baseBuilder, FileStatus status) {
    OFSPath ofsPath = new OFSPath(status.getPath(), conf);
    if (ofsPath.isRoot() || ofsPath.isVolume()) {
      return CompletableFuture.completedFuture(baseBuilder);
    }

    return supplyAsync(() -> objectStore.getVolume(ofsPath.getVolumeName()))
        .thenApply(volume -> getBucket(volume, ofsPath))
        .thenApply(bucket -> enrichedBuilder(baseBuilder, bucket, ofsPath))
        .exceptionally(error -> {
          log.warn("Error enriching file info for path {}: {}", status.getPath(), error.getMessage());
          return baseBuilder;
        });
  }

  private OzoneBucket getBucket(OzoneVolume volume, OFSPath ofsPath) {
    try {
      return volume.getBucket(ofsPath.getBucketName());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private OzoneFileInfo.Builder enrichedBuilder(
      OzoneFileInfo.Builder baseBuilder,
      OzoneBucket bucket,
      OFSPath ofsPath
  ) {
    if (ofsPath.isBucket()) {
      return enrichFileBuilder(baseBuilder, bucket.getReplicationConfig());
    }

    try {
      OzoneKeyDetails key = bucket.getKey(ofsPath.getKeyName());
      return enrichFileBuilder(baseBuilder, key.getReplicationConfig());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private OzoneFileInfo.Builder enrichFileBuilder(
      OzoneFileInfo.Builder baseBuilder,
      ReplicationConfig replicationConfig) {

    if (replicationConfig instanceof ReplicatedReplicationConfig) {
      int replicationFactor = ((ReplicatedReplicationConfig) replicationConfig)
          .getReplicationFactor()
          .getNumber();
      return baseBuilder.blockReplication((short) replicationFactor);
    }

    if (replicationConfig instanceof ECReplicationConfig) {
      ECReplicationConfig erConfig = (ECReplicationConfig) replicationConfig;
      return baseBuilder
          .erasureCodingPolicy(erConfig.getReplication())
          .blockReplication(DEFAULT_BLOCK_REPLICATION);
    }

    return baseBuilder.blockReplication(DEFAULT_BLOCK_REPLICATION);
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
    return executeInParallel(entities.stream(), transformer);
  }

  private <T> CompletableFuture<Void> executeInParallel(
      Iterator<T> entitiesIter,
      Function<T, CompletableFuture<?>> transformer) {
    Stream<T> stream = StreamSupport.stream(
        Spliterators.spliteratorUnknownSize(entitiesIter, 0), false);
    return executeInParallel(stream, transformer);
  }

  private <T> CompletableFuture<Void> executeInParallel(
      Stream<T> entities,
      Function<T, CompletableFuture<?>> transformer) {
    throwIfClosed();
    return CompletableFuture.allOf(
        entities.map(transformer::apply)
            .toArray(CompletableFuture[]::new)
    );
  }

  private void throwIfClosed() {
    if (isClosed.get()) {
      throw new CancellationException("HmsEventSource is closed");
    }
  }

  private void handleError(Throwable exception) {
    log.error("Error polling file statuses from Ozone", exception);
    close();
  }

  Path getOriginalFilePath(Path snapshotPath) {
    OFSPath ofsPath = new OFSPath(snapshotPath, conf);

    if (!ofsPath.isKey()) {
      return snapshotPath;
    }

    return new Path(
        snapshotPath.toUri().getScheme(),
        ofsPath.getAuthority(),
        ofsPath.getNonKeyPath() + ofsSnapshotKeyToPath(ofsPath)
    );
  }

  private String pathWithoutAuthority(Path path) {
    return path.toUri().getPath();
  }

  private String ofsSnapshotKeyToPath(OFSPath ofsPath) {
    String ofsKey = ofsPath.getKeyName();
    int snapshotsDirEnd = ofsKey.indexOf(PATH_DELIMITER);
    if (snapshotsDirEnd == -1) {
      return ofsKey;
    }

    int snapshotDirEnd = ofsKey.indexOf(PATH_DELIMITER, snapshotsDirEnd + 1);
    if (snapshotDirEnd == -1) {
      return ofsKey;
    }

    return ofsKey.substring(snapshotDirEnd);
  }
}
