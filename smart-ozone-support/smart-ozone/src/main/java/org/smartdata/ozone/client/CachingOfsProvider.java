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

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.ozone.RootedOzoneFileSystem;
import org.apache.hadoop.fs.ozone.SmartRootedOzoneFileSystem;
import org.smartdata.hdfs.action.HadoopAction;
import org.smartdata.hdfs.client.BaseFileSystemCache;
import org.smartdata.hdfs.client.FileSystemCache;
import org.smartdata.hdfs.client.LocalFileSystemProvider;
import org.smartdata.hdfs.impersonation.UserImpersonationStrategy;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;

import static org.smartdata.conf.SmartConfKeys.SMART_CLIENT_CONCURRENT_REPORT_ENABLED;
import static org.smartdata.ozone.OzoneSmartConf.getOzoneDefaultFsUriSetBySsm;
import static org.smartdata.utils.ConfigUtil.getSsmMasterRpcAddress;

@Slf4j
@RequiredArgsConstructor
public class CachingOfsProvider implements LocalFileSystemProvider<FileSystem> {

  private final FileSystemCache<SmartRootedOzoneFileSystem> smartFsCache;
  private final FileSystemCache<FileSystem> defaultFsCache;

  public CachingOfsProvider(
      Configuration config,
      UserImpersonationStrategy userImpersonationStrategy) {
    Duration cacheKeyTtlDuration = FileSystemCache.getCacheTtl(config);
    this.smartFsCache = new SmartFileSystemCache(userImpersonationStrategy, cacheKeyTtlDuration);
    this.defaultFsCache = new DefaultFileSystemCache(userImpersonationStrategy, cacheKeyTtlDuration);
  }

  @Override
  public FileSystem provide(Configuration config, String user, HadoopAction.FsType fsType)
      throws IOException {
    return fsType == HadoopAction.FsType.SMART
        ? smartFsCache.get(config, user, getSsmMasterRpcAddress(config))
        : defaultFsCache.get(config, user, null);
  }

  @Override
  public void close() throws IOException {
    smartFsCache.close();
    defaultFsCache.close();
  }

  private static class SmartFileSystemCache extends BaseFileSystemCache<SmartRootedOzoneFileSystem> {

    private SmartFileSystemCache(
        UserImpersonationStrategy userImpersonationStrategy,
        Duration keyTtl) {
      super(userImpersonationStrategy, keyTtl);
    }

    @Override
    protected URI getServiceUri(Configuration config) {
      return getOzoneDefaultFsUriSetBySsm(config);
    }

    @Override
    protected SmartRootedOzoneFileSystem createFileSystem(Configuration config, CacheKey cacheKey) {
      try {
        Configuration fsConfig = new Configuration(config);
        // a smart server always has only 1 address set
        // in the "smart.server.rpc.address" option
        fsConfig.setBoolean(SMART_CLIENT_CONCURRENT_REPORT_ENABLED, false);
        SmartRootedOzoneFileSystem fileSystem = new SmartRootedOzoneFileSystem();
        fileSystem.initialize(cacheKey.getServiceUri(), fsConfig);
        return fileSystem;
      } catch (IOException exception) {
        throw new RuntimeException("Error creating smart file system", exception);
      }
    }
  }

  private static class DefaultFileSystemCache extends BaseFileSystemCache<FileSystem> {
    private DefaultFileSystemCache(
        UserImpersonationStrategy userImpersonationStrategy,
        Duration keyTtl) {
      super(userImpersonationStrategy, keyTtl);
    }

    @Override
    protected URI getServiceUri(Configuration config) {
      return getOzoneDefaultFsUriSetBySsm(config);
    }

    @Override
    protected FileSystem createFileSystem(Configuration config, CacheKey cacheKey) {
      try {
        RootedOzoneFileSystem fileSystem = new RootedOzoneFileSystem();
        fileSystem.initialize(cacheKey.getServiceUri(), config);
        return fileSystem;
      } catch (IOException exception) {
        throw new RuntimeException("Error creating default file system", exception);
      }
    }
  }
}
