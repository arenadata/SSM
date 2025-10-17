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
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.smartdata.hadoop.filesystem.SmartFileSystem;
import org.smartdata.hdfs.action.HdfsAction;
import org.smartdata.hdfs.impersonation.UserImpersonationStrategy;
import org.smartdata.utils.StringUtil;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Duration;

import static org.smartdata.conf.SmartConfKeys.SMART_ACTION_CLIENT_CACHE_TTL_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_ACTION_CLIENT_CACHE_TTL_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_CLIENT_CONCURRENT_REPORT_ENABLED;
import static org.smartdata.hdfs.HadoopUtil.doAsCurrentUser;
import static org.smartdata.utils.ConfigUtil.getSsmMasterRpcAddress;

@Slf4j
@RequiredArgsConstructor
public class CachingLocalFileSystemProvider implements LocalFileSystemProvider {

  private final FileSystemCache<SmartFileSystem> smartFsCache;
  private final FileSystemCache<DistributedFileSystem> defaultFsCache;

  public CachingLocalFileSystemProvider(
      Configuration config,
      UserImpersonationStrategy userImpersonationStrategy) {
    String cacheKeyTtl = config.get(
        SMART_ACTION_CLIENT_CACHE_TTL_KEY, SMART_ACTION_CLIENT_CACHE_TTL_DEFAULT);
    Duration cacheKeyTtlDuration = Duration.ofMillis(
        StringUtil.parseTimeString(cacheKeyTtl));

    this.smartFsCache = new SmartFileSystemCache(userImpersonationStrategy, cacheKeyTtlDuration);
    this.defaultFsCache = new DefaultFileSystemCache(userImpersonationStrategy, cacheKeyTtlDuration);
  }

  @Override
  public DistributedFileSystem provide(Configuration config, String user, HdfsAction.FsType fsType)
      throws IOException {
    InetSocketAddress ssmMasterAddress = getSsmMasterRpcAddress(config);

    return fsType == HdfsAction.FsType.SMART
        ? smartFsCache.get(config, user, ssmMasterAddress)
        // we don't rely on SSM in case of pure HDFS client
        : defaultFsCache.get(config, user, null);
  }

  @Override
  public void close() throws IOException {
    smartFsCache.close();
    defaultFsCache.close();
  }

  private static class SmartFileSystemCache extends BaseFileSystemCache<SmartFileSystem> {

    private SmartFileSystemCache(
        UserImpersonationStrategy userImpersonationStrategy,
        Duration keyTtl) {
      super(userImpersonationStrategy, keyTtl);
    }

    @Override
    protected SmartFileSystem createFileSystem(Configuration config, CacheKey cacheKey) {
      try {
        Configuration fsConfig = new Configuration(config);
        // smart server always have only 1 address set
        // in the "smart.server.rpc.address" option
        fsConfig.setBoolean(SMART_CLIENT_CONCURRENT_REPORT_ENABLED, false);
        return createSmartFileSystem(config, cacheKey);
      } catch (IOException exception) {
        throw new RuntimeException("Error creating smart file system", exception);
      }
    }

    private SmartFileSystem createSmartFileSystem(
        Configuration config, CacheKey cacheKey) throws IOException {
      SmartDFSClient smartDfsClient = new SmartDFSClient(
          cacheKey.getNameNodeUri(), config, cacheKey.getSsmMasterAddress());
      SmartFileSystem fileSystem = new SmartFileSystem(smartDfsClient);
      fileSystem.initialize(cacheKey.getNameNodeUri(), config);
      return fileSystem;
    }
  }

  private static class DefaultFileSystemCache extends BaseFileSystemCache<DistributedFileSystem> {
    private DefaultFileSystemCache(
        UserImpersonationStrategy userImpersonationStrategy,
        Duration keyTtl) {
      super(userImpersonationStrategy, keyTtl);
    }

    @Override
    protected DistributedFileSystem createFileSystem(Configuration config, CacheKey cacheKey) {
      try {
        DistributedFileSystem fileSystem = new DistributedFileSystem();
        fileSystem.initialize(cacheKey.getNameNodeUri(), config);
        return fileSystem;
      } catch (IOException exception) {
        throw new RuntimeException("Error creating default file system", exception);
      }
    }
  }
}
