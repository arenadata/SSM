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
package org.smartdata.integration;

import com.google.common.collect.ImmutableMap;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.IOUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.smartdata.client.generated.model.CachedFileInfoDto;
import org.smartdata.client.generated.model.CachedFilesDto;
import org.smartdata.client.generated.model.FileAccessCountsDto;
import org.smartdata.client.generated.model.FileAccessInfoDto;
import org.smartdata.integration.api.ActionsApiWrapper;
import org.smartdata.integration.api.FilesApiWrapper;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestFilesRestApi extends IntegrationTestBase {

  private static final long INOTIFY_FETCHER_POLL_PERIOD_MS = 100;

  private FilesApiWrapper apiClient;
  private ActionsApiWrapper actionsApiWrapper;

  @Before
  public void createApi() {
    apiClient = new FilesApiWrapper();
    actionsApiWrapper = new ActionsApiWrapper();
  }

  @Test
  public void testGetEmptyAccessCounts() {
    FileAccessCountsDto accessCounts = apiClient.getAccessCounts();

    assertEquals(0, accessCounts.getTotal().longValue());
    assertTrue(accessCounts.getItems().isEmpty());
  }

  @Test
  public void testGetAccessCounts() {
    Map<String, Integer> expectedAccessCounts = ImmutableMap.of(
        "/tmp/file1", 4,
        "/tmp/file2", 3,
        "/tmp/file3", 1
    );

    expectedAccessCounts.entrySet().stream()
        .peek(entry -> createFile(entry.getKey()))
        .forEach(entry -> accessFile(entry.getKey(), entry.getValue()));

    retryUntil(
        apiClient::getAccessCounts,
        actualAccessCounts -> accessCountsEquals(actualAccessCounts, expectedAccessCounts),
        Duration.ofMillis(100),
        Duration.ofMinutes(1)
    );
  }

  @Test
  public void testGetEmptyCachedFiles() {
    CachedFilesDto cachedFiles = apiClient.getCachedFiles();

    assertEquals(0, cachedFiles.getTotal().longValue());
    assertTrue(cachedFiles.getItems().isEmpty());
  }

  @Test
  @Ignore("TODO recheck it when ADH-4648 will be merged")
  public void testGetCachedFiles() {
    Map<String, Integer> expectedAccessCounts = ImmutableMap.of(
        "/tmp/file1", 4,
        "/tmp/file2", 3,
        "/tmp/file3", 1
    );

    expectedAccessCounts.entrySet().stream()
        .peek(entry -> createFile(entry.getKey()))
        .peek(entry -> cacheFile(entry.getKey()))
        .forEach(entry -> accessFile(entry.getKey(), entry.getValue()));

    retryUntil(
        apiClient::getCachedFiles,
        actualAccessCounts -> cachedFilesEquals(actualAccessCounts, expectedAccessCounts),
        Duration.ofMillis(100),
        Duration.ofSeconds(30)
    );
  }

  @Override
  protected void createFile(String path) {
    super.createFile(path);
    // we need to wait until SSM fetches INotify file create event
    // to put these file in metastore before we access them
    waitUntilInotifyEventPulled();
  }

  private void waitUntilInotifyEventPulled() {
    try {
      Thread.sleep(5 * INOTIFY_FETCHER_POLL_PERIOD_MS);
    } catch (InterruptedException e) {
      Assert.fail("Error waiting for inotify event to be pulled");
    }
  }

  private void cacheFile(String file) {
    actionsApiWrapper.waitTillActionFinished(
        "cache -file " + file,
        Duration.ofMillis(100),
        Duration.ofSeconds(1)
    );
  }

  private boolean cachedFilesEquals(CachedFilesDto cachedFiles,
                                    Map<String, Integer> expectedAccessCounts) {
    return expectedAccessCounts.size() == cachedFiles.getTotal()
        && expectedAccessCounts.size() == cachedFiles.getItems().size()
        && cachedFiles.getItems()
        .stream()
        .collect(Collectors.toMap(
            CachedFileInfoDto::getPath,
            CachedFileInfoDto::getAccessCount,
            Integer::sum
        )).equals(expectedAccessCounts);
  }

  private boolean accessCountsEquals(FileAccessCountsDto accessCounts,
                                     Map<String, Integer> expectedAccessCounts) {
    return expectedAccessCounts.size() == accessCounts.getTotal()
        && expectedAccessCounts.size() == accessCounts.getItems().size()
        && accessCounts.getItems()
        .stream()
        .collect(Collectors.toMap(
            FileAccessInfoDto::getPath,
            FileAccessInfoDto::getAccessCount,
            Integer::sum
        )).equals(expectedAccessCounts);
  }

  private void accessFile(String file, int times) {
    if (times < 1) {
      return;
    }

    Path path = new Path(file);

    for (int i = 0; i < times; ++i) {
      try (FSDataInputStream inputStream = cluster.getFileSystem().open(path)) {
        IOUtils.readFullyToByteArray(inputStream);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }
  }
}
