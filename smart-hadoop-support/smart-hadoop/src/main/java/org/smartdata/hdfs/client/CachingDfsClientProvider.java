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
package org.smartdata.hdfs.client;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hdfs.DFSClient;
import org.smartdata.hdfs.HadoopUtil;
import org.smartdata.hdfs.action.HdfsAction;
import org.smartdata.utils.StringUtil;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Duration;

import static org.smartdata.conf.SmartConfKeys.SMART_ACTION_CLIENT_CACHE_TTL_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_ACTION_CLIENT_CACHE_TTL_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_CLIENT_CONCURRENT_REPORT_ENABLED;
import static org.smartdata.utils.ConfigUtil.getSsmMasterRpcAddress;

@Slf4j
@RequiredArgsConstructor
public class CachingDfsClientProvider implements DfsClientProvider {

  private final DfsClientCache<SmartDFSClient> smartClientCache;
  private final DfsClientCache<DFSClient> hdfsClientCache;

  public CachingDfsClientProvider(Configuration config) {
    String cacheKeyTtl = config.get(
        SMART_ACTION_CLIENT_CACHE_TTL_KEY, SMART_ACTION_CLIENT_CACHE_TTL_DEFAULT);
    Duration cacheKeyTtlDuration = Duration.ofMillis(
        StringUtil.parseTimeString(cacheKeyTtl)
    );

    this.smartClientCache = new SmartDfsClientCache(cacheKeyTtlDuration);
    this.hdfsClientCache = new HdfsClientCache(cacheKeyTtlDuration);
  }

  @Override
  public DFSClient provide(Configuration config, HdfsAction.DfsClientType clientType)
      throws IOException {
    InetSocketAddress ssmMasterAddress = getSsmMasterRpcAddress(config);

    return clientType == HdfsAction.DfsClientType.SMART
        ? smartClientCache.get(config, ssmMasterAddress)
        // we don't rely on SSM in case of pure HDFS client
        : hdfsClientCache.get(config, null);
  }

  @Override
  public void close() throws IOException {
    smartClientCache.close();
    hdfsClientCache.close();
  }

  private static class SmartDfsClientCache extends BaseDfsClientCache<SmartDFSClient> {

    private SmartDfsClientCache(Duration keyTtl) {
      super(keyTtl);
    }

    @Override
    protected SmartDFSClient createDfsClient(Configuration config, CacheKey cacheKey) {
      try {
        Configuration clientConfig = new Configuration(config);
        // smart server always have only 1 address set
        // in the "smart.server.rpc.address" option
        clientConfig.setBoolean(SMART_CLIENT_CONCURRENT_REPORT_ENABLED, false);
        return new SmartDFSClient(
            cacheKey.getNameNodeUri(), config, cacheKey.getSsmMasterAddress());
      } catch (IOException exception) {
        throw new RuntimeException("Error creating smart client", exception);
      }
    }
  }

  private static class HdfsClientCache extends BaseDfsClientCache<DFSClient> {
    private HdfsClientCache(Duration keyTtl) {
      super(keyTtl);
    }

    @Override
    protected DFSClient createDfsClient(Configuration config, CacheKey cacheKey) {
      try {
        return HadoopUtil.getDFSClient(cacheKey.getNameNodeUri(), config);
      } catch (IOException exception) {
        throw new RuntimeException("Error creating hdfs client", exception);
      }
    }
  }
}
