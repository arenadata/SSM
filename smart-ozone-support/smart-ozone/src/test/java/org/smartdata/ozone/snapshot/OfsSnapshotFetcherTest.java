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

import lombok.Data;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.ozone.client.OzoneBucket;
import org.apache.hadoop.ozone.client.OzoneVolume;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.ozone.OzoneClusterHarness;
import org.smartdata.ozone.model.FsObjectStreamRecord;
import org.smartdata.ozone.model.OzoneFileInfo;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static java.util.stream.IntStream.range;
import static org.junit.Assert.assertEquals;

public class OfsSnapshotFetcherTest extends OzoneClusterHarness {
  private static final int SNAPSHOT_FETCH_TIMEOUT_SEC = 10;

  private static final int VOLUMES_COUNT = 2;
  private static final int BUCKETS_PER_VOL_COUNT = 4;
  private static final int KEYS_PER_BUCKET_COUNT = 3;
  private static final int DIRS_PER_BUCKET_COUNT = 4;
  private static final int SUBDIRS_PER_DIR_COUNT = 3;
  private static final int KEYS_PER_DIR_COUNT = 3;
  private static final int KEYS_PER_SUBDIR_COUNT = 2;

  private final static int TOTAL_EVENTS_PER_DIR_COUNT =
      1 + KEYS_PER_DIR_COUNT + SUBDIRS_PER_DIR_COUNT * (1 + KEYS_PER_SUBDIR_COUNT);

  private final static int TOTAL_EVENTS_PER_BUCKET_COUNT =
      1 + KEYS_PER_BUCKET_COUNT + DIRS_PER_BUCKET_COUNT * TOTAL_EVENTS_PER_DIR_COUNT;

  private final static int TOTAL_EVENTS_PER_VOLUME_COUNT =
      1 + BUCKETS_PER_VOL_COUNT * TOTAL_EVENTS_PER_BUCKET_COUNT;

  // 1 for EOF event and 1 for s3v bucket for s3 related keys
  private final static int TOTAL_EVENTS_COUNT =
      2 + VOLUMES_COUNT * TOTAL_EVENTS_PER_VOLUME_COUNT;

  private OfsSnapshotFetcher fetcher;

  @Before
  public void initFetcher() throws IOException {
    fetcher = OfsSnapshotFetcher.builder()
        .fs(FileSystem.get(ozoneConf))
        .objectStore(ozoneClient)
        .conf(ozoneConf)
        .executor(Executors.newFixedThreadPool(8))
        .batchSize(TOTAL_EVENTS_COUNT + 2)
        .build();

    initFs();
  }

  @After
  public void closeFetcher() {
    fetcher.close();
  }

  @Test
  public void testFetchKeys() throws Exception {
    fetcher.runSnapshotAsync().get(SNAPSHOT_FETCH_TIMEOUT_SEC, TimeUnit.SECONDS);

    BlockingQueue<FsObjectStreamRecord> outputQueue = fetcher.getOutputQueue();
    assertEquals(TOTAL_EVENTS_COUNT, outputQueue.size());

    Set<FileView> actualFiles = outputQueue.stream()
        .filter(OzoneFileInfo.class::isInstance)
        .map(OzoneFileInfo.class::cast)
        .map(this::toFileView)
        .collect(Collectors.toSet());

    assertEquals(expectedFiles(), actualFiles);
  }

  private FileView toFileView(OzoneFileInfo fileInfo) {
    return new FileView(
        fileInfo.getPath(),
        fileInfo.getLength(),
        fileInfo.isVolume(),
        fileInfo.isBucket()
    );
  }

  private void initFs() {
    range(0, VOLUMES_COUNT)
        .forEach(this::initVolume);
  }

  private Set<FileView> expectedFiles() {
    Set<FileView> expected = new HashSet<>();

    expected.add(volumeInfo("/s3v"));

    range(0, VOLUMES_COUNT).forEach(vIdx -> {
      String volPath = "/vol" + vIdx;
      expected.add(volumeInfo(volPath));

      range(0, BUCKETS_PER_VOL_COUNT).forEach(bIdx -> {
        String buckPath = volPath + "/buck" + bIdx;
        expected.add(bucketInfo(buckPath));

        range(0, KEYS_PER_BUCKET_COUNT).forEach(kIdx ->
            expected.add(keyInfo(buckPath + "/key" + kIdx)));

        range(0, DIRS_PER_BUCKET_COUNT).forEach(dIdx -> {
          String dirPath = buckPath + "/dir" + dIdx;
          expected.add(dirInfo(dirPath));

          range(0, KEYS_PER_DIR_COUNT).forEach(kIdx ->
              expected.add(keyInfo(dirPath + "/key" + kIdx)));

          range(0, SUBDIRS_PER_DIR_COUNT).forEach(sdIdx -> {
            String sdPath = dirPath + "/subdir" + sdIdx;
            expected.add(dirInfo(sdPath));

            range(0, KEYS_PER_SUBDIR_COUNT).forEach(kIdx ->
                expected.add(keyInfo(sdPath + "/key" + kIdx)));
          });
        });
      });
    });

    return expected;
  }

  private FileView volumeInfo(String path) {
    return new FileView(path, 0, true, false);
  }

  private FileView bucketInfo(String path) {
    return new FileView(path, 0, false, true);
  }

  private FileView dirInfo(String path) {
    return new FileView(path, 0, false, false);
  }

  private FileView keyInfo(String path) {
    String fileData = Arrays.stream(path.split("/"))
        // skip root, volume and bucket
        .skip(3)
        .collect(Collectors.joining("/")) + "_data";

    return new FileView(path,
        fileData.getBytes(StandardCharsets.UTF_8).length, false, false);
  }

  private void initVolume(int volumeIdx) {
    try {
      String volumeName = "vol" + volumeIdx;
      ozoneClient.createVolume(volumeName);
      OzoneVolume volume = ozoneClient.getVolume(volumeName);

      range(0, BUCKETS_PER_VOL_COUNT)
          .forEach(idx -> initBucket(volume, idx));
    } catch (IOException e) {
      throw new RuntimeException("Failed to initialize volume " + volumeIdx, e);
    }
  }

  private void initBucket(OzoneVolume volume, int bucketIdx) {
    try {
      String bucketName = "buck" + bucketIdx;
      volume.createBucket(bucketName);
      OzoneBucket bucket = volume.getBucket(bucketName);

      range(0, KEYS_PER_BUCKET_COUNT).forEach(idx ->
          createKey(bucket, "key" + idx));

      range(0, DIRS_PER_BUCKET_COUNT).forEach(idx ->
          initDirectory(bucket, idx));

    } catch (IOException e) {
      throw new RuntimeException("Failed to initialize bucket " + bucketIdx, e);
    }
  }

  private void initDirectory(OzoneBucket bucket, int dirIdx) {
    try {
      String dirPath = "dir" + dirIdx;
      bucket.createDirectory(dirPath);

      range(0, KEYS_PER_DIR_COUNT).forEach(idx ->
          createKey(bucket, dirPath + "/key" + idx));

      range(0, SUBDIRS_PER_DIR_COUNT).forEach(idx ->
          initSubdirectory(bucket, dirPath, idx));

    } catch (IOException e) {
      throw new RuntimeException("Failed to initialize directory " + dirIdx, e);
    }
  }

  private void initSubdirectory(OzoneBucket bucket, String parentPath, int dirIdx) {
    try {
      String subDirPath = parentPath + "/subdir" + dirIdx;
      bucket.createDirectory(subDirPath);

      range(0, KEYS_PER_SUBDIR_COUNT).forEach(idx ->
          createKey(bucket, subDirPath + "/key" + idx));

    } catch (IOException e) {
      throw new RuntimeException("Failed to initialize subdirectory " + dirIdx, e);
    }
  }

  private void createKey(OzoneBucket bucket, String keyName) {
    try {
      createKey(bucket, keyName, keyName + "_data");
    } catch (IOException e) {
      throw new RuntimeException("Failed to create key: " + keyName, e);
    }
  }

  @Data
  private static class FileView {
    private final String path;
    private final long length;
    private final boolean isVolume;
    private final boolean isBucket;
  }
}