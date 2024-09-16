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

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hdfs.DFSClient;
import org.cache2k.Cache;
import org.cache2k.Cache2kBuilder;
import org.cache2k.CacheEntry;
import org.cache2k.event.CacheEntryEvictedListener;
import org.smartdata.hdfs.HadoopUtil;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;

@Slf4j
public abstract class BaseDfsClientCache<T extends DFSClient> implements DfsClientCache<T> {

  private final Cache<CacheKey, T> clientCache;

  public BaseDfsClientCache(Duration keyTtl, Class<T> valueClazz) {
    this.clientCache = Cache2kBuilder.of(CacheKey.class, valueClazz)
        .idleScanTime(keyTtl)
        .addListener((CacheEntryEvictedListener<CacheKey, T>) this::onEntryEvicted)
        .disableMonitoring(true)
        .disableStatistics(true)
        .build();
  }

  @Override
  public T get(Configuration config, InetSocketAddress ssmMasterAddress)
      throws IOException {
    CacheKey cacheKey = new CacheKey(ssmMasterAddress, HadoopUtil.getNameNodeUri(config));
    return clientCache.computeIfAbsent(cacheKey,
        key -> createDfsClient(config, key));
  }

  @Override
  public void close() throws IOException {
    for (T dfsClient : clientCache.asMap().values()) {
      try {
        dfsClient.close();
      } catch (IOException exception) {
        log.error("Error closing cached dfsClient", exception);
      }
    }
    clientCache.close();
  }

  protected abstract T createDfsClient(Configuration config, CacheKey cacheKey);

  private void onEntryEvicted(
      Cache<CacheKey, T> cache, CacheEntry<CacheKey, T> entry) throws IOException {
    entry.getValue().close();
  }

  @Data
  protected static class CacheKey {
    private final InetSocketAddress ssmMasterAddress;
    private final URI nameNodeUri;
  }
}
