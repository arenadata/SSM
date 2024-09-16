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

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.smartdata.utils.ConfigUtil;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * SSM related configurations as well as HDFS configurations.
 */
public class SmartConf extends Configuration {
  private static final Logger LOG = LoggerFactory.getLogger(SmartConf.class);
  // Include hosts configured in conf/agents and
  // hosts added dynamically (by `start-agent.sh --host $host`)
  private Set<String> agentHosts;
  private Set<String> serverHosts;

  public SmartConf() {
    Configuration.addDefaultResource("smart-default.xml");
    Configuration.addDefaultResource("smart-site.xml");

    parseHostsFiles();
  }

  public List<String> getCoverDirs() {
    return ConfigUtil.getCoverDirs(this);
  }

  /**
   * Add host for newly launched standby server after SSM cluster
   * becomes active.
   */
  public void addServerHosts(String hostname) {
    serverHosts.add(hostname);
  }

  public Set<String> getServerHosts() {
    return serverHosts;
  }

  /**
   * Add host for newly launched agents after SSM cluster
   * becomes active.
   */
  public void addAgentHost(String hostname) {
    agentHosts.add(hostname);
  }

  public Set<String> getAgentHosts() {
    return agentHosts;
  }

  /**
   * Get password for druid by Configuration.getPassword().
   */
  public Optional<String> getPasswordFromHadoop(String name) throws IOException {
    return Optional.ofNullable(getPassword(name))
        .map(String::new);
  }

  public Map<String, String> asMap(Predicate<String> keyFilter) {
    return StreamSupport.stream(spliterator(), false)
        .filter(entry -> keyFilter.test(entry.getKey()))
        .collect(Collectors.toMap(
            Map.Entry::getKey,
            Map.Entry::getValue
        ));
  }

  public String getNonEmpty(String key) {
    return getNonEmpty(key, "Required option not provided: " + key);
  }

  public String getNonEmpty(String key, String errorText) {
    return Optional.ofNullable(get(key))
        .filter(StringUtils::isNotBlank)
        .orElseThrow(() -> new IllegalArgumentException(errorText));
  }

  public Map<String, String> asMap() {
    return asMap(key -> true);
  }

  private void parseHostsFiles() {
    SsmHostsFileReader ssmHostsFileReader = new SsmHostsFileReader();

    try {
      this.serverHosts = parseHostsFile(ssmHostsFileReader, "servers");
      this.agentHosts = parseHostsFile(ssmHostsFileReader, "agents");
    } catch (IOException exception) {
      // In some unit tests, these files may be missing. So such exception is tolerable.
      LOG.error("Error parsing SSM servers/agents hosts file", exception);
    }
  }

  private Set<String> parseHostsFile(
      SsmHostsFileReader hostFileReader, String fileName) throws IOException {
    String configDir = get(
        SmartConfKeys.SMART_CONF_DIR_KEY,
        SmartConfKeys.SMART_CONF_DIR_DEFAULT);

    Path hostsFilePath = Paths.get(configDir, fileName);
    return hostFileReader.parse(hostsFilePath);
  }
}
