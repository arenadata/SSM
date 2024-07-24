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
package org.smartdata.hdfs;

import org.apache.commons.lang.ClassUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.ClassLoaderUtils;
import org.apache.hadoop.util.VersionInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CompatibilityHelperLoader {
  public static final Logger LOG =
      LoggerFactory.getLogger(CompatibilityHelperLoader.class);

  private static final String HADOOP_3_HELPER_CLASS = "org.smartdata.hdfs.CompatibilityHelper3";
  public static final String DEFAULT_HDFS_VERSION = "3.2.4";
  public static final String UNKNOWN_VERSION = "Unknown";

  private static class CompatibilityHelperHolder {
    static final CompatibilityHelper INSTANCE = createCompatibilityHelper(
        VersionInfo.getVersion());
  }

  public static CompatibilityHelper getHelper() {
    return CompatibilityHelperHolder.INSTANCE;
  }

  static CompatibilityHelper createCompatibilityHelper(String version) {
    if (StringUtils.isBlank(version) || version.equalsIgnoreCase(UNKNOWN_VERSION)) {
      LOG.error("Cannot get Hadoop version. Using default version: " + DEFAULT_HDFS_VERSION);
      version = DEFAULT_HDFS_VERSION;
    }
    String[] parts = version.split("\\.");
    if (parts.length < 2) {
      throw new IllegalArgumentException(
          "Illegal Hadoop Version, expected 'Major.Minor.*' format: " + version);
    }

    int majorVersion = Integer.parseInt(parts[0]);
    int minorVersion = Integer.parseInt(parts[1]);

    if (majorVersion < 3 || minorVersion < 2) {
      throw new IllegalArgumentException("Hadoop versions below 3.2.X are not supported");
    }

    return create(HADOOP_3_HELPER_CLASS);
  }

  private static CompatibilityHelper create(String classString) {
    try {
      Class<?> clazz = ClassUtils.getClass(classString);
      return (CompatibilityHelper) clazz.newInstance();
    } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
      throw new RuntimeException("Error loading HDFS compatibility helper", e);
    }
  }
}
