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
package org.smartdata.conf;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SsmHostsFileReader {
  private static final Logger LOG = LoggerFactory.getLogger(SsmHostsFileReader.class);
  private static final String LOCALHOST = "localhost";
  private static final String COMMENT_PREFIX = "#";

  private final String localHostname;

  public SsmHostsFileReader() {
    localHostname = getLocalHostname();
  }

  public Set<String> parse(Path instancesFile) throws IOException {
    try (Stream<String> hosts = Files.lines(instancesFile)) {
      return hosts
          .filter(host -> !StringUtils.isBlank(host) && !host.startsWith(COMMENT_PREFIX))
          .map(this::maybeReplaceLocalhost)
          .collect(Collectors.toSet());
    } catch (IOException exception) {
      LOG.error("Error reading SSM instances file {}", instancesFile, exception);
      throw new IOException(exception);
    }
  }

  private String maybeReplaceLocalhost(String address) {
    return localHostname != null && LOCALHOST.equalsIgnoreCase(address)
        ? localHostname
        : address;
  }

  private String getLocalHostname() {
      try {
        InetAddress address = InetAddress.getLocalHost();
        return address.getHostName();
      } catch (UnknownHostException exception) {
        LOG.warn("Localhost name could not be resolved", exception);
        return null;
      }
  }
}
