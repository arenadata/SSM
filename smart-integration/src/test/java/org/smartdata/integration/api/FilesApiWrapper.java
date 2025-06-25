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
package org.smartdata.integration.api;

import io.restassured.response.Response;
import org.eclipse.jetty.http.HttpStatus;
import org.smartdata.client.generated.api.FilesApi;
import org.smartdata.client.generated.invoker.ApiClient;
import org.smartdata.client.generated.model.CachedFileInfoDto;
import org.smartdata.client.generated.model.CachedFilesDto;
import org.smartdata.client.generated.model.FileAccessCountsDto;
import org.smartdata.client.generated.model.FileAccessInfoDto;

import java.time.Duration;
import java.util.Map;
import java.util.stream.Collectors;

import static org.smartdata.integration.IntegrationTestBase.retryUntil;

public class FilesApiWrapper {

  private final FilesApi apiClient;

  public FilesApiWrapper() {
    this.apiClient = ApiClient.api(ApiClient.Config.apiConfig()).files();
  }

  public FileAccessCountsDto getAccessCounts() {
    return apiClient.getAccessCounts()
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .executeAs(Response::andReturn);
  }

  public CachedFilesDto getCachedFiles() {
    return apiClient.getCachedFiles()
        .respSpec(response -> response.expectStatusCode(HttpStatus.OK_200))
        .executeAs(Response::andReturn);
  }

  public FilesApi rawClient() {
    return apiClient;
  }

  public void waitGetAccessCountsEquals(Map<String, Integer> expectedAccessCounts, Duration interval,
                                        Duration timeout) {
    retryUntil(
        this::getAccessCounts,
        accessCounts -> accessCountsEquals(accessCounts, expectedAccessCounts),
        interval,
        timeout
    );
  }

  public void waitGetCachedAccessCountsEquals(Map<String, Integer> expectedAccessCounts, Duration interval,
                                              Duration timeout) {
    retryUntil(
        this::getCachedFiles,
        cachedFiles -> cachedFilesEquals(cachedFiles, expectedAccessCounts),
        interval,
        timeout
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
