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
package org.smartdata.client.activeserver;

import com.google.common.net.HostAndPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Optional;

/**
 * Record active server (hostname:port) into a local file.
 * This file can be dropped by OS, but considering it's just used for
 * optimization, the lack of the recorded active server doesn't cause critical
 * issue.
 */
public class ActiveServerAddressFileCache implements ActiveServerAddressCache {
  static final Logger LOG = LoggerFactory.getLogger(ActiveServerAddressFileCache.class);

  private final Path filePath;

  public ActiveServerAddressFileCache(Path filePath) {
    this.filePath = filePath;
  }

  @Override
  public void put(InetSocketAddress serverAddress) {
    try {
      Files.write(
          filePath,
          HostAndPort.fromParts(serverAddress.getHostString(), serverAddress.getPort())
              .toString()
              .getBytes(StandardCharsets.UTF_8),
          StandardOpenOption.CREATE);
    } catch (IOException exception) {
      // we log to debug to avoid messing up hdfs cli commands output
      LOG.debug("Error saving active server address in the file {}", filePath, exception);
    }
  }

  @Override
  public Optional<InetSocketAddress> get() {
    try {
      byte[] addressBytes = Files.readAllBytes(filePath);
      HostAndPort hostAndPort = HostAndPort.fromString(
          new String(addressBytes, StandardCharsets.UTF_8));
      InetSocketAddress serverAddress =
          new InetSocketAddress(hostAndPort.getHost(), hostAndPort.getPort());
      return Optional.of(serverAddress);
    } catch (Exception exception) {
      // we log to debug to avoid messing up hdfs cli commands output
      LOG.debug("Error fetching active server address from the file {}", filePath, exception);
      return Optional.empty();
    }
  }
}
