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
package org.smartdata.hdfs.compression;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.compress.Compressor;
import org.smartdata.LoadableService;

import java.io.IOException;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;


public interface CompressorFactory extends LoadableService {
  String codec();

  Compressor createCompressor(Configuration config, int bufferSize) throws IOException;

  // TODO what do these magic numbers mean?
  /** Compression overhead of given codec. */
  default int compressionOverhead(int bufferSize) {
    // taken from Hadoop 3.3.6 sources
    return bufferSize / 100 + 12;
  }

  static Map<String, CompressorFactory> loadAll() {
    return LoadableService.loadAll(CompressorFactory.class)
        .collect(Collectors.toMap(
            CompressorFactory::codec,
            Function.identity()
        ));
  }
}
