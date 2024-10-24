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

import org.apache.hadoop.conf.Configuration;

import java.net.InetSocketAddress;
import java.nio.file.Paths;
import java.util.Optional;

import static org.smartdata.conf.SmartConfKeys.SMART_CLIENT_ACTIVE_SERVER_CACHE_PATH_DEFAULT;
import static org.smartdata.conf.SmartConfKeys.SMART_CLIENT_ACTIVE_SERVER_CACHE_PATH_KEY;

public interface ActiveServerAddressCache {
  void put(InetSocketAddress serverAddress);

  Optional<InetSocketAddress> get();

  static ActiveServerAddressCache fileCache(Configuration conf) {
    String cacheFilePath = conf.get(
        SMART_CLIENT_ACTIVE_SERVER_CACHE_PATH_KEY,
        SMART_CLIENT_ACTIVE_SERVER_CACHE_PATH_DEFAULT);

    return new ActiveServerAddressFileCache(Paths.get(cacheFilePath));
  }
}
