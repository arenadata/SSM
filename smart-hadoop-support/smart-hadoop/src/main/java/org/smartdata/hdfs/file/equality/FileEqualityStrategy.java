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
package org.smartdata.hdfs.file.equality;

import java.util.Objects;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.model.BaseFileInfo;
import org.smartdata.model.FileInfo;

public interface FileEqualityStrategy {
  enum Strategy {
    FILE_LENGTH,
    CHECKSUM
  }

  boolean areEqual(BaseFileInfo srcFileInfo, FileStatus destFileStatus);

  static FileEqualityStrategy from(Configuration conf) {
    String rawStrategy = conf.get(
        SmartConfKeys.SMART_SYNC_FILE_EQUALITY_STRATEGY,
        SmartConfKeys.SMART_SYNC_FILE_EQUALITY_STRATEGY_DEFAULT);
    try {
      return of(Strategy.valueOf(rawStrategy.toUpperCase()), conf);
    } catch (IllegalArgumentException illegalArgumentException) {
      throw new IllegalArgumentException("Wrong file compare strategy: " + rawStrategy);
    }
  }

  static FileEqualityStrategy of(Strategy strategy, Configuration conf) {
    if (Objects.requireNonNull(strategy) == Strategy.CHECKSUM) {
      return new ChecksumFileEqualityStrategy(conf);
    }
    return new LengthFileEqualityStrategy();
  }
}
