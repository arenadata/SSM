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
import io.restassured.response.Response;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.IOUtils;
import org.eclipse.jetty.http.HttpStatus;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.smartdata.client.generated.model.CachedFileInfoDto;
import org.smartdata.client.generated.model.CachedFileSortDto;
import org.smartdata.client.generated.model.CachedFilesDto;
import org.smartdata.client.generated.model.CachedTimeIntervalDto;
import org.smartdata.client.generated.model.FileAccessCountsDto;
import org.smartdata.client.generated.model.FileAccessInfoDto;
import org.smartdata.client.generated.model.HotFileSortDto;
import org.smartdata.client.generated.model.LastAccessedTimeIntervalDto;
import org.smartdata.client.generated.model.PageRequestDto;
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
  private static final Duration INTERVAL = Duration.ofMillis(100);
  private static final Duration TIMEOUT = Duration.ofSeconds(30);
  private static final Map<String, Integer> EXPECTED_ACCESS_COUNTS = ImmutableMap.of(
      "/tmp/file1", 4,
      "/tmp/file2", 1
  );

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
    EXPECTED_ACCESS_COUNTS.entrySet().stream()
        .peek(entry -> createFile(entry.getKey()))
        .forEach(entry -> accessFile(entry.getKey(), entry.getValue()));

    waitGetAccessCountsEquals(EXPECTED_ACCESS_COUNTS);
  }

  @Test
  public void testGetEmptyCachedFiles() {
    CachedFilesDto cachedFiles = apiClient.getCachedFiles();

    assertEquals(0, cachedFiles.getTotal().longValue());
    assertTrue(cachedFiles.getItems().isEmpty());
  }

  @Test
  public void testGetCachedFiles() {
    EXPECTED_ACCESS_COUNTS.entrySet().stream()
        .peek(entry -> createFile(entry.getKey()))
        .peek(entry -> cacheFile(entry.getKey()))
        .forEach(entry -> accessFile(entry.getKey(), entry.getValue()));

    waitGetCachedAccessCountsEquals(EXPECTED_ACCESS_COUNTS);
  }

  @Test
  public void testGetAccessCountsPagination() {
    EXPECTED_ACCESS_COUNTS.entrySet().stream()
        .peek(entry -> createFile(entry.getKey()))
        .forEach(entry -> accessFile(entry.getKey(), entry.getValue()));

    waitGetAccessCountsEquals(EXPECTED_ACCESS_COUNTS);

    FileAccessCountsDto fileAccessCounts = apiClient.rawClient()
        .getAccessCounts()
        .sortQuery(HotFileSortDto.PATH)
        .reqSpec(request -> request
            .addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, 1)
            .addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, 1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(FileAccessCountsDto.class);

    assertEquals(2, fileAccessCounts.getTotal().longValue());
    assertEquals(1, fileAccessCounts.getItems().size());

    FileAccessInfoDto fetchedInfo = fileAccessCounts.getItems().get(0);
    assertEquals("/tmp/file2", fetchedInfo.getPath());
    assertEquals(1, fetchedInfo.getAccessCount().longValue());
  }

  @Test
  public void testGetAccessCountsSortById() {
    EXPECTED_ACCESS_COUNTS.entrySet().stream()
        .peek(entry -> createFile(entry.getKey()))
        .forEach(entry -> accessFile(entry.getKey(), entry.getValue()));

    waitGetAccessCountsEquals(EXPECTED_ACCESS_COUNTS);

    // ASC
    FileAccessCountsDto fileAccessCounts = apiClient.rawClient()
        .getAccessCounts()
        .sortQuery(HotFileSortDto.ID)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(FileAccessCountsDto.class);

    FileAccessInfoDto firstSortedInfo = fileAccessCounts.getItems().get(0);
    FileAccessInfoDto secondSortedInfo = fileAccessCounts.getItems().get(1);

    assertEquals("/tmp/file1", firstSortedInfo.getPath());
    assertEquals("/tmp/file2", secondSortedInfo.getPath());

    // DESC
    fileAccessCounts = apiClient.rawClient()
        .getAccessCounts()
        .sortQuery(HotFileSortDto._ID)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(FileAccessCountsDto.class);

    firstSortedInfo = fileAccessCounts.getItems().get(0);
    secondSortedInfo = fileAccessCounts.getItems().get(1);

    assertEquals("/tmp/file2", firstSortedInfo.getPath());
    assertEquals("/tmp/file1", secondSortedInfo.getPath());
  }

  @Test
  public void testGetAccessCountsSortByPath() {
    EXPECTED_ACCESS_COUNTS.entrySet().stream()
        .peek(entry -> createFile(entry.getKey()))
        .forEach(entry -> accessFile(entry.getKey(), entry.getValue()));

    waitGetAccessCountsEquals(EXPECTED_ACCESS_COUNTS);

    // ASC
    FileAccessCountsDto fileAccessCounts = apiClient.rawClient()
        .getAccessCounts()
        .sortQuery(HotFileSortDto.PATH)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(FileAccessCountsDto.class);

    FileAccessInfoDto firstSortedInfo = fileAccessCounts.getItems().get(0);
    FileAccessInfoDto secondSortedInfo = fileAccessCounts.getItems().get(1);

    assertEquals("/tmp/file1", firstSortedInfo.getPath());
    assertEquals("/tmp/file2", secondSortedInfo.getPath());

    // DESC
    fileAccessCounts = apiClient.rawClient()
        .getAccessCounts()
        .sortQuery(HotFileSortDto._PATH)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(FileAccessCountsDto.class);

    firstSortedInfo = fileAccessCounts.getItems().get(0);
    secondSortedInfo = fileAccessCounts.getItems().get(1);

    assertEquals("/tmp/file2", firstSortedInfo.getPath());
    assertEquals("/tmp/file1", secondSortedInfo.getPath());
  }

  @Test
  public void testGetAccessCountsSortByAccessCount() {
    EXPECTED_ACCESS_COUNTS.entrySet().stream()
        .peek(entry -> createFile(entry.getKey()))
        .forEach(entry -> accessFile(entry.getKey(), entry.getValue()));

    waitGetAccessCountsEquals(EXPECTED_ACCESS_COUNTS);

    // ASC
    FileAccessCountsDto fileAccessCounts = apiClient.rawClient()
        .getAccessCounts()
        .sortQuery(HotFileSortDto.ACCESSCOUNT)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(FileAccessCountsDto.class);

    FileAccessInfoDto firstSortedInfo = fileAccessCounts.getItems().get(0);
    FileAccessInfoDto secondSortedInfo = fileAccessCounts.getItems().get(1);

    assertEquals("/tmp/file2", firstSortedInfo.getPath());
    assertEquals("/tmp/file1", secondSortedInfo.getPath());

    // DESC
    fileAccessCounts = apiClient.rawClient()
        .getAccessCounts()
        .sortQuery(HotFileSortDto._ACCESSCOUNT)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(FileAccessCountsDto.class);

    firstSortedInfo = fileAccessCounts.getItems().get(0);
    secondSortedInfo = fileAccessCounts.getItems().get(1);

    assertEquals("/tmp/file1", firstSortedInfo.getPath());
    assertEquals("/tmp/file2", secondSortedInfo.getPath());
  }

  @Test
  @Ignore("TODO ADH-6189: incorrect column used when sort by LastAccessTime. 500 status code")
  public void testGetAccessCountsSortByLastAccessTime() {
    EXPECTED_ACCESS_COUNTS.entrySet().stream()
        .peek(entry -> createFile(entry.getKey()))
        .forEach(entry -> accessFile(entry.getKey(), entry.getValue()));

    waitGetAccessCountsEquals(EXPECTED_ACCESS_COUNTS);

    // ASC
    FileAccessCountsDto fileAccessCounts = apiClient.rawClient()
        .getAccessCounts()
        .sortQuery(HotFileSortDto.LASTACCESSTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(FileAccessCountsDto.class);

    FileAccessInfoDto firstSortedInfo = fileAccessCounts.getItems().get(0);
    FileAccessInfoDto secondSortedInfo = fileAccessCounts.getItems().get(1);

    assertEquals("/tmp/file1", firstSortedInfo.getPath());
    assertEquals("/tmp/file2", secondSortedInfo.getPath());

    // DESC
    fileAccessCounts = apiClient.rawClient()
        .getAccessCounts()
        .sortQuery(HotFileSortDto._LASTACCESSTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(FileAccessCountsDto.class);

    firstSortedInfo = fileAccessCounts.getItems().get(0);
    secondSortedInfo = fileAccessCounts.getItems().get(1);

    assertEquals("/tmp/file2", firstSortedInfo.getPath());
    assertEquals("/tmp/file1", secondSortedInfo.getPath());
  }

  @Test
  public void testGetAccessCountsFilterByPathLike() {
    EXPECTED_ACCESS_COUNTS.entrySet().stream()
        .peek(entry -> createFile(entry.getKey()))
        .forEach(entry -> accessFile(entry.getKey(), entry.getValue()));

    waitGetAccessCountsEquals(EXPECTED_ACCESS_COUNTS);

    FileAccessCountsDto fileAccessCounts = apiClient.rawClient()
        .getAccessCounts()
        .pathLikeQuery("%/file2%")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(FileAccessCountsDto.class);

    assertEquals(1, fileAccessCounts.getTotal().longValue());
    assertEquals(1, fileAccessCounts.getItems().size());

    FileAccessInfoDto fetchedInfo = fileAccessCounts.getItems().get(0);
    assertEquals("/tmp/file2", fetchedInfo.getPath());
    assertEquals(1, fetchedInfo.getAccessCount().longValue());
  }

  @Test
  public void testGetAccessCountsFilterByLastAccessTime() {
    String firstFilePath = "/tmp/file1";
    String secondFilePath = "/tmp/file2";
    createFile(firstFilePath);
    createFile(secondFilePath);
    accessFile(firstFilePath, 1);

    retryUntil(
        apiClient::getAccessCounts,
        accessCounts -> accessCounts.getItems().stream()
            .anyMatch(info -> info.getPath().equals(firstFilePath) && info.getAccessCount() == 1),
        Duration.ofMillis(100),
        Duration.ofSeconds(30)
    );

    long start = System.currentTimeMillis();
    accessFile(secondFilePath, 1);
    long end = System.currentTimeMillis();

    retryUntil(
        apiClient::getAccessCounts,
        accessCounts -> accessCounts.getItems().stream()
            .anyMatch(info -> info.getPath().equals(secondFilePath) && info.getAccessCount() == 1),
        Duration.ofMillis(100),
        Duration.ofSeconds(30)
    );

    FileAccessCountsDto fileAccessCounts = apiClient.rawClient()
        .getAccessCounts()
        .reqSpec(request -> request
            .addQueryParam(LastAccessedTimeIntervalDto.JSON_PROPERTY_LAST_ACCESSED_TIME_FROM, start)
            .addQueryParam(LastAccessedTimeIntervalDto.JSON_PROPERTY_LAST_ACCESSED_TIME_TO, end))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(FileAccessCountsDto.class);

    assertEquals(1, fileAccessCounts.getTotal().longValue());
    assertEquals(1, fileAccessCounts.getItems().size());

    FileAccessInfoDto fetchedInfo = fileAccessCounts.getItems().get(0);
    assertEquals("/tmp/file2", fetchedInfo.getPath());
    assertEquals(1, fetchedInfo.getAccessCount().longValue());
  }

  @Test
  public void testGetCachedPagination() {
    EXPECTED_ACCESS_COUNTS.entrySet().stream()
        .peek(entry -> createFile(entry.getKey()))
        .peek(entry -> cacheFile(entry.getKey()))
        .forEach(entry -> accessFile(entry.getKey(), entry.getValue()));

    waitGetCachedAccessCountsEquals(EXPECTED_ACCESS_COUNTS);

    CachedFilesDto cachedFiles = apiClient.rawClient()
        .getCachedFiles()
        .sortQuery(CachedFileSortDto.PATH)
        .reqSpec(request -> request
            .addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, 1)
            .addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, 1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CachedFilesDto.class);

    assertEquals(2, cachedFiles.getTotal().longValue());
    assertEquals(1, cachedFiles.getItems().size());

    CachedFileInfoDto fetchedInfo = cachedFiles.getItems().get(0);
    assertEquals("/tmp/file2", fetchedInfo.getPath());
    assertEquals(1, fetchedInfo.getAccessCount().longValue());
  }

  @Test
  public void testGetCachedSortById() {
    EXPECTED_ACCESS_COUNTS.entrySet().stream()
        .peek(entry -> createFile(entry.getKey()))
        .peek(entry -> cacheFile(entry.getKey()))
        .forEach(entry -> accessFile(entry.getKey(), entry.getValue()));

    waitGetCachedAccessCountsEquals(EXPECTED_ACCESS_COUNTS);

    // ASC
    CachedFilesDto cachedFiles = apiClient.rawClient()
        .getCachedFiles()
        .sortQuery(CachedFileSortDto.ID)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CachedFilesDto.class);

    CachedFileInfoDto firstSortedInfo = cachedFiles.getItems().get(0);
    CachedFileInfoDto secondSortedInfo = cachedFiles.getItems().get(1);

    assertEquals("/tmp/file1", firstSortedInfo.getPath());
    assertEquals("/tmp/file2", secondSortedInfo.getPath());

    // DESC
    cachedFiles = apiClient.rawClient()
        .getCachedFiles()
        .sortQuery(CachedFileSortDto._ID)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CachedFilesDto.class);

    firstSortedInfo = cachedFiles.getItems().get(0);
    secondSortedInfo = cachedFiles.getItems().get(1);

    assertEquals("/tmp/file2", firstSortedInfo.getPath());
    assertEquals("/tmp/file1", secondSortedInfo.getPath());
  }

  @Test
  public void testGetCachedSortByPath() {
    EXPECTED_ACCESS_COUNTS.entrySet().stream()
        .peek(entry -> createFile(entry.getKey()))
        .peek(entry -> cacheFile(entry.getKey()))
        .forEach(entry -> accessFile(entry.getKey(), entry.getValue()));

    waitGetCachedAccessCountsEquals(EXPECTED_ACCESS_COUNTS);

    // ASC
    CachedFilesDto cachedFiles = apiClient.rawClient()
        .getCachedFiles()
        .sortQuery(CachedFileSortDto.PATH)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CachedFilesDto.class);

    CachedFileInfoDto firstSortedInfo = cachedFiles.getItems().get(0);
    CachedFileInfoDto secondSortedInfo = cachedFiles.getItems().get(1);

    assertEquals("/tmp/file1", firstSortedInfo.getPath());
    assertEquals("/tmp/file2", secondSortedInfo.getPath());

    // DESC
    cachedFiles = apiClient.rawClient()
        .getCachedFiles()
        .sortQuery(CachedFileSortDto._PATH)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CachedFilesDto.class);

    firstSortedInfo = cachedFiles.getItems().get(0);
    secondSortedInfo = cachedFiles.getItems().get(1);

    assertEquals("/tmp/file2", firstSortedInfo.getPath());
    assertEquals("/tmp/file1", secondSortedInfo.getPath());
  }

  @Test
  public void testGetCachedSortByAccessCount() {
    EXPECTED_ACCESS_COUNTS.entrySet().stream()
        .peek(entry -> createFile(entry.getKey()))
        .peek(entry -> cacheFile(entry.getKey()))
        .forEach(entry -> accessFile(entry.getKey(), entry.getValue()));

    waitGetCachedAccessCountsEquals(EXPECTED_ACCESS_COUNTS);

    // ASC
    CachedFilesDto cachedFiles = apiClient.rawClient()
        .getCachedFiles()
        .sortQuery(CachedFileSortDto.ACCESSCOUNT)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CachedFilesDto.class);

    CachedFileInfoDto firstSortedInfo = cachedFiles.getItems().get(0);
    CachedFileInfoDto secondSortedInfo = cachedFiles.getItems().get(1);

    assertEquals("/tmp/file2", firstSortedInfo.getPath());
    assertEquals("/tmp/file1", secondSortedInfo.getPath());

    // DESC
    cachedFiles = apiClient.rawClient()
        .getCachedFiles()
        .sortQuery(CachedFileSortDto._ACCESSCOUNT)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CachedFilesDto.class);

    firstSortedInfo = cachedFiles.getItems().get(0);
    secondSortedInfo = cachedFiles.getItems().get(1);

    assertEquals("/tmp/file1", firstSortedInfo.getPath());
    assertEquals("/tmp/file2", secondSortedInfo.getPath());
  }

  @Test
  public void testGetCachedSortByLastAccessTime() {
    EXPECTED_ACCESS_COUNTS.entrySet().stream()
        .peek(entry -> createFile(entry.getKey()))
        .peek(entry -> cacheFile(entry.getKey()))
        .forEach(entry -> accessFile(entry.getKey(), entry.getValue()));

    waitGetCachedAccessCountsEquals(EXPECTED_ACCESS_COUNTS);

    // ASC
    CachedFilesDto cachedFiles = apiClient.rawClient()
        .getCachedFiles()
        .sortQuery(CachedFileSortDto.LASTACCESSTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CachedFilesDto.class);

    CachedFileInfoDto firstSortedInfo = cachedFiles.getItems().get(0);
    CachedFileInfoDto secondSortedInfo = cachedFiles.getItems().get(1);

    assertEquals("/tmp/file1", firstSortedInfo.getPath());
    assertEquals("/tmp/file2", secondSortedInfo.getPath());

    // DESC
    cachedFiles = apiClient.rawClient()
        .getCachedFiles()
        .sortQuery(CachedFileSortDto._LASTACCESSTIME)
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CachedFilesDto.class);

    firstSortedInfo = cachedFiles.getItems().get(0);
    secondSortedInfo = cachedFiles.getItems().get(1);

    assertEquals("/tmp/file2", firstSortedInfo.getPath());
    assertEquals("/tmp/file1", secondSortedInfo.getPath());
  }

  @Test
  public void testGetCachedFilterByPathLike() {
    EXPECTED_ACCESS_COUNTS.entrySet().stream()
        .peek(entry -> createFile(entry.getKey()))
        .peek(entry -> cacheFile(entry.getKey()))
        .forEach(entry -> accessFile(entry.getKey(), entry.getValue()));

    waitGetCachedAccessCountsEquals(EXPECTED_ACCESS_COUNTS);

    CachedFilesDto cachedFiles = apiClient.rawClient()
        .getCachedFiles()
        .pathLikeQuery("%/file2%")
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CachedFilesDto.class);

    CachedFileInfoDto fetchedInfo = cachedFiles.getItems().get(0);
    assertEquals("/tmp/file2", fetchedInfo.getPath());
  }

  @Test
  public void testGetCachedFilterByLastAccessTime() {
    Map<String, Integer> expectedAccessCounts = ImmutableMap.of(
        "/tmp/file1", 0,
        "/tmp/file2", 1,
        "/tmp/file3", 2
    );

    expectedAccessCounts.entrySet().stream()
        .peek(entry -> createFile(entry.getKey()))
        .peek(entry -> cacheFile(entry.getKey()))
        .forEach(entry -> accessFile(entry.getKey(), entry.getValue()));

    waitGetCachedAccessCountsEquals(expectedAccessCounts);

    long start = System.currentTimeMillis();
    accessFile("/tmp/file3", 1);
    retryUntil(
        apiClient::getCachedFiles,
        cachedFiles -> cachedFiles.getItems().stream()
            .anyMatch(info -> info.getPath().equals("/tmp/file3") && info.getAccessCount() == 3),
        Duration.ofMillis(100),
        Duration.ofSeconds(30)
    );
    long end = System.currentTimeMillis();

    CachedFilesDto cachedFiles = apiClient.rawClient()
        .getCachedFiles()
        .reqSpec(request -> request
            .addQueryParam(LastAccessedTimeIntervalDto.JSON_PROPERTY_LAST_ACCESSED_TIME_FROM, start)
            .addQueryParam(LastAccessedTimeIntervalDto.JSON_PROPERTY_LAST_ACCESSED_TIME_TO, end))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CachedFilesDto.class);

    CachedFileInfoDto fetchedInfo = cachedFiles.getItems().get(0);
    assertEquals("/tmp/file3", fetchedInfo.getPath());
  }

  @Test
  public void testGetCachedFilterByCacheTime() {
    String firstFileName = "/tmp/file1";
    String secondFileName = "/tmp/file2";

    createFile(firstFileName);
    createFile(secondFileName);
    cacheFile(firstFileName);
    long start = System.currentTimeMillis();
    cacheFile(secondFileName);
    long end = System.currentTimeMillis();

    CachedFilesDto cachedFiles = apiClient.rawClient()
        .getCachedFiles()
        .reqSpec(request -> request
            .addQueryParam(CachedTimeIntervalDto.JSON_PROPERTY_CACHED_TIME_FROM, start)
            .addQueryParam(CachedTimeIntervalDto.JSON_PROPERTY_CACHED_TIME_TO, end))
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .execute(Response::body)
        .as(CachedFilesDto.class);

    CachedFileInfoDto fetchedInfo = cachedFiles.getItems().get(0);
    assertEquals("/tmp/file2", fetchedInfo.getPath());
  }

  @Test
  public void testGetAccessCountsPaginationWithIncorrectValue() {
    apiClient.rawClient()
        .getAccessCounts()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, 0))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getAccessCounts()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, -1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getAccessCounts()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, -1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getAccessCounts()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, "string"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getAccessCounts()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, "string"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
  }

  @Test
  public void testGetAccessCountsSortByIncorrectQuery() {
    apiClient.rawClient()
        .getAccessCounts()
        .sortQuery("nonexistent")
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
  }

  @Test
  public void testGetCachedPaginationWithIncorrectValue() {
    apiClient.rawClient()
        .getCachedFiles()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, 0))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getCachedFiles()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, -1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getCachedFiles()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, -1))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getCachedFiles()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_LIMIT, "string"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);

    apiClient.rawClient()
        .getCachedFiles()
        .reqSpec(request -> request.addQueryParam(PageRequestDto.JSON_PROPERTY_OFFSET, "string"))
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
  }

  @Test
  public void testGetCachedSortByIncorrectQuery() {
    apiClient.rawClient()
        .getCachedFiles()
        .sortQuery("nonexistent")
        .respSpec(response -> response.expectStatusCode(HttpStatus.BAD_REQUEST_400))
        .execute(Response::andReturn);
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
    // Wait until cached files will be processed
    retryUntil(
        apiClient::getCachedFiles,
        cachedFiles -> cachedFiles.getItems().stream()
            .anyMatch(i -> i.getPath().equals(file)),
        Duration.ofMillis(100),
        Duration.ofSeconds(30)
    );
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

  private void waitGetAccessCountsEquals(Map<String, Integer> expectedAccessCounts) {
    retryUntil(
        apiClient::getAccessCounts,
        accessCounts -> accessCountsEquals(accessCounts, expectedAccessCounts),
        INTERVAL,
        TIMEOUT
    );
  }

  private void waitGetCachedAccessCountsEquals(Map<String, Integer> expectedAccessCounts) {
    retryUntil(
        apiClient::getCachedFiles,
        cachedFiles -> cachedFilesEquals(cachedFiles, expectedAccessCounts),
        INTERVAL,
        TIMEOUT
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
}
