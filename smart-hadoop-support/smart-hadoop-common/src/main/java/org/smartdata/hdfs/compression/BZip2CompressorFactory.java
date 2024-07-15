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
import org.apache.hadoop.io.compress.bzip2.Bzip2Compressor;
import org.apache.hadoop.io.compress.bzip2.Bzip2Decompressor;
import org.apache.hadoop.io.compress.bzip2.Bzip2Factory;

import java.io.IOException;


public class BZip2CompressorFactory implements CompressorFactory, DecompressorFactory {
  public static final String BZIP2_CODEC = "Zlib";

  @Override
  public String codec() {
    return BZIP2_CODEC;
  }

  @Override
  public Compressor createCompressor(Configuration config, int bufferSize) throws IOException {
    if (Bzip2Factory.isNativeBzip2Loaded(config)) {
      return new Bzip2Compressor(
          Bzip2Factory.getBlockSize(config),
          Bzip2Factory.getWorkFactor(config),
          bufferSize);
    }
    throw new IOException("Failed to load/initialize native-bzip2 library");
  }

  @Override
  public Decompressor createDecompressor(Configuration config, int bufferSize) throws IOException {
    if (Bzip2Factory.isNativeBzip2Loaded(config)) {
      return new Bzip2Decompressor(false, bufferSize);
    }
    throw new IOException("Failed to load/initialize native-bzip2 library");

  }
}
