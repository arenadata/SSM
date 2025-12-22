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

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.smartdata.utils.StringUtil;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Duration;

import static org.smartdata.conf.SmartConfKeys.SMART_ACTION_CLIENT_CACHE_TTL_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_ACTION_CLIENT_CACHE_TTL_KEY;

public interface FileSystemCache<T extends FileSystem> extends Closeable {
  T get(Configuration config, String user, InetSocketAddress ssmMasterAddress) throws IOException;

  static Duration getCacheTtl(Configuration configuration) {
    String cacheKeyTtl = configuration.get(
        SMART_ACTION_CLIENT_CACHE_TTL_KEY, SMART_ACTION_CLIENT_CACHE_TTL_DEFAULT);
    return Duration.ofMillis(StringUtil.parseTimeString(cacheKeyTtl));
  }
}
