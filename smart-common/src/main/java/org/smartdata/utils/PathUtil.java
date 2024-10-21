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
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;

import java.io.IOException;
import java.net.URI;
import java.util.Optional;

import static org.smartdata.utils.ConfigUtil.toRemoteClusterConfig;

public class PathUtil {
  private static final String DIR_SEP = "/";
  private static final String HDFS_SCHEME = "hdfs";
  private static final String[] GLOBS = new String[]{
      "*", "?"
  };

  public static String getBaseDir(String path) {
    if (path == null) {
      return null;
    }

    int last = path.lastIndexOf(DIR_SEP);
    if (last == -1) {
      return null;
    }

    int first = path.length();
    for (String g : GLOBS) {
      int gIdx = path.indexOf(g);
      if (gIdx >= 0) {
        first = Math.min(gIdx, first);
      }
    }

    last = path.substring(0, first).lastIndexOf(DIR_SEP);
    if (last == -1) {
      return null;
    }
    return path.substring(0, last + 1);
  }

  public static String addPathSeparator(String path) {
    return Optional.ofNullable(path)
        .filter(p -> !p.endsWith(DIR_SEP))
        .map(p -> p + DIR_SEP)
        .orElse(path);
  }

  public static boolean pathStartsWith(String path, String prefixToCheck) {
    return addPathSeparator(path)
        .startsWith(addPathSeparator(prefixToCheck));
  }

  // todo replace 'stringPath.startsWith("hdfs")' calls with this method
  public static boolean isAbsoluteRemotePath(Path path) {
    return Optional.ofNullable(path)
        .map(Path::toUri)
        .filter(PathUtil::isAbsoluteRemotePath)
        .isPresent();
  }

  public static FileSystem getRemoteFileSystem(
      Path path, Configuration conf) throws IOException {
    return path.getFileSystem(toRemoteClusterConfig(conf));
  }

  public static boolean isAbsoluteRemotePath(URI uri) {
    return Optional.ofNullable(uri)
        .map(URI::getScheme)
        .filter(HDFS_SCHEME::equals)
        .isPresent();
  }
}
