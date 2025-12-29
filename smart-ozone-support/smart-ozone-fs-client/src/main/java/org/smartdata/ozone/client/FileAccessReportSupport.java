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
package org.smartdata.ozone.client;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.fs.Path;
import org.smartdata.metrics.FileAccessEvent;
import org.smartdata.protocol.SmartClientProtocol;

import java.io.Closeable;
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Collectors;

import static org.smartdata.utils.SecurityUtil.getCurrentUsername;

@Slf4j
public class FileAccessReportSupport implements Closeable {
  private final SmartClientProtocol ssmClient;

  @Getter
  private final String basePath;

  public FileAccessReportSupport(SmartClientProtocol ssmClient, String... basePathSegments) {
    this.ssmClient = ssmClient;
    this.basePath = Arrays.stream(basePathSegments)
        .collect(Collectors.joining("/", "/", ""));
  }

  public void reportFileAccess(String path) {
    String pathWithoutAuthority = new Path(basePath, removeLeadingSlash(path))
        .toUri()
        .getPath();

    FileAccessEvent accessEvent = new FileAccessEvent(
        pathWithoutAuthority,
        getCurrentUsername().orElse(null));

    try {
      ssmClient.reportFileAccessEvent(accessEvent);
    } catch (IOException exception) {
      // todo add retry mechanism for both HDFS and Ozone clients
      log.error("Error reporting file access event", exception);
    }
  }

  private String removeLeadingSlash(String path) {
    return path.startsWith("/") ? path.substring(1) : path;
  }

  @Override
  public void close() throws IOException {
    ssmClient.close();
  }
}
