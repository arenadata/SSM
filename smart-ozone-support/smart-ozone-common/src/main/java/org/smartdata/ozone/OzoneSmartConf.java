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
package org.smartdata.ozone;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.ozone.RootedOzoneFileSystem;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;

import java.net.URI;
import java.util.Optional;

import static org.apache.hadoop.fs.FileSystem.DEFAULT_FS;
import static org.apache.hadoop.fs.FileSystem.FS_DEFAULT_NAME_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_OZONE_RPC_SERVER_KEY;

public class OzoneSmartConf extends OzoneConfiguration {
  public static final String OZONE_FETCH_BATCH_SIZE = "smart.ozone.event.fetch.batch.size";
  public static final int OZONE_FETCH_BATCH_SIZE_DEFAULT = 8192;

  public static final String OZONE_SNAPSHOT_THREADS_COUNT = "smart.ozone.snapshot.threads.count";
  public static final int OZONE_SNAPSHOT_THREADS_COUNT_DEFAULT = 16;

  public OzoneSmartConf(Configuration conf) {
    super(conf);

    set("fs.ofs.impl", RootedOzoneFileSystem.class.getName());
    loadSystemProperties();
  }

  public int getFetchBatchSize() {
    return getInt(OZONE_FETCH_BATCH_SIZE, OZONE_FETCH_BATCH_SIZE_DEFAULT);
  }

  public int getSnapshotFetcherThreadsCount() {
    return getInt(OZONE_SNAPSHOT_THREADS_COUNT, OZONE_SNAPSHOT_THREADS_COUNT_DEFAULT);
  }

  public URI getOzoneDefaultFsUri() {
    return getDefaultFsIfSet()
        .map(URI::create)
        .orElseGet(() -> getOzoneDefaultFsFromRpc(this));
  }

  private Optional<String> getDefaultFsIfSet() {
    return Optional.ofNullable(get(FS_DEFAULT_NAME_KEY))
        .filter(StringUtils::isNoneBlank)
        .filter(fs -> !fs.equals(DEFAULT_FS));
  }

  private void loadSystemProperties() {
    for (String propertyName : getProps().stringPropertyNames()) {
      String systemPropertyValue = System.getProperty(propertyName);
      if (systemPropertyValue != null) {
        set(propertyName, systemPropertyValue);
      }
    }
  }

  private Optional<URI> getOzoneRpcAddress() {
    return Optional.ofNullable(get("ozone.om.address"))
        .map(url -> "ofs://" + url)
        .map(URI::create);
  }

  public static URI getOzoneDefaultFsUri(Configuration conf) {
    return new OzoneSmartConf(conf).getOzoneDefaultFsUri();
  }

  public static URI getOzoneDefaultFsUriSetBySsm(Configuration conf) {
    return Optional.ofNullable(conf.get(SMART_OZONE_RPC_SERVER_KEY))
        .map(URI::create)
        .orElseGet(() -> getOzoneDefaultFsUri(conf));
  }

  private static URI getOzoneDefaultFsFromRpc(OzoneSmartConf ozoneConf) {
    return Optional.ofNullable(ozoneConf)
        .flatMap(OzoneSmartConf::getOzoneRpcAddress)
        .orElseThrow(() -> new IllegalArgumentException("Ozone RPC address is not set"));
  }
}
