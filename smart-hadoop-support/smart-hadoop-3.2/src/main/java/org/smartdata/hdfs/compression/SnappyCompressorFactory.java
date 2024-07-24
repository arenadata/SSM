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
import org.apache.hadoop.io.compress.Decompressor;
import org.apache.hadoop.io.compress.SnappyCodec;
import org.apache.hadoop.io.compress.snappy.SnappyCompressor;
import org.apache.hadoop.io.compress.snappy.SnappyDecompressor;

import java.io.IOException;

public class SnappyCompressorFactory implements CompressorFactory, DecompressorFactory {
  public static final String SNAPPY_CODEC = "snappy";

  @Override
  public String codec() {
    return SNAPPY_CODEC;
  }

  // TODO what does these magic numbers mean?
  @Override
  public int compressionOverhead(int bufferSize) {
    // taken from Hadoop 3.2.4 org.apache.hadoop.io.compress.SnappyCodec sources
    return bufferSize / 6 + 32;
  }

  @Override
  public Compressor createCompressor(Configuration config, int bufferSize) throws IOException {
    if (SnappyCodec.isNativeCodeLoaded()) {
      return new SnappyCompressor(bufferSize);
    }
    throw new IOException("Failed to load/initialize native-snappy library");
  }

  @Override
  public Decompressor createDecompressor(Configuration config, int bufferSize) throws IOException {
    if (SnappyCodec.isNativeCodeLoaded()) {
      return new SnappyDecompressor(bufferSize);
    }
    throw new IOException("Failed to load/initialize native-snappy library");
  }
}
