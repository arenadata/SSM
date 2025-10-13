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
package org.smartdata.hive.client;

import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.hive.metastore.HiveMetaStoreUtils;
import org.apache.hadoop.hive.metastore.IMetaStoreClient;
import org.smartdata.hdfs.impersonation.UserImpersonationStrategy;

import java.util.concurrent.TimeUnit;

import static org.smartdata.hive.HiveSmartConf.HMS_CLIENT_CACHE_INITIAL_CAPACITY;
import static org.smartdata.hive.HiveSmartConf.HMS_CLIENT_CACHE_INITIAL_CAPACITY_DEFAULT;
import static org.smartdata.hive.HiveSmartConf.HMS_CLIENT_CACHE_MAX_CAPACITY;
import static org.smartdata.hive.HiveSmartConf.HMS_CLIENT_CACHE_MAX_CAPACITY_DEFAULT;
import static org.smartdata.hive.HiveSmartConf.HMS_CLIENT_CACHE_TTL_MS;
import static org.smartdata.hive.HiveSmartConf.HMS_CLIENT_CACHE_TTL_MS_DEFAULT;

@Slf4j
public class CachingMetaStoreClientProvider implements MetaStoreClientProvider {
  private final HiveConf baseHiveConf;
  private final UserImpersonationStrategy impersonationStrategy;

  public CachingMetaStoreClientProvider(
      Configuration configuration,
      UserImpersonationStrategy impersonationStrategy) {
    this.impersonationStrategy = impersonationStrategy;
    this.baseHiveConf = new HiveConf(configuration, HiveConf.class);
    baseHiveConf.setBoolVar(HiveConf.ConfVars.METASTORE_CLIENT_CACHE_ENABLED, true);
    baseHiveConf.setTimeVar(HiveConf.ConfVars.METASTORE_CLIENT_CACHE_EXPIRY_TIME,
        configuration.getLong(HMS_CLIENT_CACHE_TTL_MS, HMS_CLIENT_CACHE_TTL_MS_DEFAULT),
        TimeUnit.MILLISECONDS);
    baseHiveConf.setIntVar(HiveConf.ConfVars.METASTORE_CLIENT_CACHE_INITIAL_CAPACITY,
        configuration.getInt(HMS_CLIENT_CACHE_INITIAL_CAPACITY, HMS_CLIENT_CACHE_INITIAL_CAPACITY_DEFAULT));
    baseHiveConf.setIntVar(HiveConf.ConfVars.METASTORE_CLIENT_CACHE_MAX_CAPACITY,
        configuration.getInt(HMS_CLIENT_CACHE_MAX_CAPACITY, HMS_CLIENT_CACHE_MAX_CAPACITY_DEFAULT));
  }

  @Override
  public IMetaStoreClient provide(String metastoreAddress, String currentUser) {
    HiveConf remoteHiveConf = new HiveConf(baseHiveConf);
    // we should use deprecated METASTORE_URIS due to the cache internal logic
    remoteHiveConf.setVar(HiveConf.ConfVars.METASTORE_URIS, metastoreAddress);

    // internal cache implementation will automatically extract both UGI
    // and current thread information
    try {
      return impersonationStrategy.runWithImpersonation(currentUser,
          () -> HiveMetaStoreUtils.getHiveMetastoreClient(remoteHiveConf));
    } catch (Exception e) {
      log.error("Fail to get metastore client", e);
      throw new RuntimeException(e);
    }
  }
}
