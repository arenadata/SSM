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
package org.apache.hadoop.hdfs;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.compress.Compressor;
import org.apache.hadoop.io.compress.Decompressor;
import org.smartdata.hdfs.compression.CompressorFactory;
import org.smartdata.hdfs.compression.DecompressorFactory;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * This class decide which compressor type for SmartCompressorStream 
 */
public class CompressionCodecFactory {
  private final Map<String, CompressorFactory> registeredCompressors;
  private final Map<String, DecompressorFactory> registeredDecompressors;
  private final Configuration config;

  private static class Holder {
    private static final CompressionCodecFactory INSTANCE = new CompressionCodecFactory(
        // pass config based on hdfs-core.xml and hdfs-core.xml
        new Configuration());
  }

  public static CompressionCodecFactory getInstance() {
    return Holder.INSTANCE;
  }

  private CompressionCodecFactory(Configuration config) {
    this.config = config;
    this.registeredCompressors = CompressorFactory.loadAll();
    this.registeredDecompressors = DecompressorFactory.loadAll();
  }

  public Set<String> getSupportedCodecs() {
    return new HashSet<>(registeredCompressors.keySet());
  }

  /**
   * Return compression overhead of given codec
   * @param bufferSize   buffSize of codec (int)
   * @param codec        codec name (String)
   * @return compression overhead (int)
   */
  public int compressionOverhead(int bufferSize, String codec) throws IOException {
    return getOrThrow(registeredCompressors, codec)
        .compressionOverhead(bufferSize);
  }

  /**
   *  Create a compressor
   */
  public Compressor createCompressor(int bufferSize, String codec) throws IOException {
    return getOrThrow(registeredCompressors, codec)
        .createCompressor(config, bufferSize);
  }

  /**
   *  Create a decompressor
   */
  public Decompressor creatDecompressor(int bufferSize, String codec) throws IOException {
    return getOrThrow(registeredDecompressors, codec)
        .createDecompressor(config, bufferSize);
  }

  private <T> T getOrThrow(
      Map<String, T> map, String key) throws IOException {
    return Optional.ofNullable(map.get(key))
        .orElseThrow(() -> new IOException(
            "Invalid compression codec: " + key + ". Available values: " + map.keySet()));
  }
}
