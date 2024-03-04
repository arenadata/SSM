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
package org.smartdata.utils;

import org.apache.hadoop.conf.Configuration;

import static org.smartdata.SmartConstants.DISTRIBUTED_FILE_SYSTEM;
import static org.smartdata.SmartConstants.FS_HDFS_IMPL;
import static org.smartdata.SmartConstants.SMART_FILE_SYSTEM;

public class ConfigUtil {
  public static Configuration toRemoteClusterConfig(Configuration configuration) {
    Configuration remoteConfig = new Configuration(configuration);
    if (SMART_FILE_SYSTEM.equals(remoteConfig.get(FS_HDFS_IMPL))) {
      remoteConfig.set(FS_HDFS_IMPL, DISTRIBUTED_FILE_SYSTEM);
    }

    return remoteConfig;
  }
}
