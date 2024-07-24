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
import org.apache.hadoop.io.compress.zlib.ZlibCompressor;
import org.apache.hadoop.io.compress.zlib.ZlibDecompressor;
import org.apache.hadoop.io.compress.zlib.ZlibFactory;
import org.apache.hadoop.util.NativeCodeLoader;


public class ZLibCompressorFactory implements CompressorFactory, DecompressorFactory {
  public static final String ZLIB_CODEC = "Zlib";

  @Override
  public String codec() {
    return ZLIB_CODEC;
  }

  @Override
  public Compressor createCompressor(Configuration config, int bufferSize) {
    if (NativeCodeLoader.isNativeCodeLoaded()) {
      return new ZlibCompressor(ZlibCompressor.CompressionLevel.DEFAULT_COMPRESSION,
          ZlibCompressor.CompressionStrategy.DEFAULT_STRATEGY,
          ZlibCompressor.CompressionHeader.DEFAULT_HEADER,
          bufferSize);
    }
    // TODO buffer size for build-in zlib codec
    return ZlibFactory.getZlibCompressor(config);
  }

  @Override
  public Decompressor createDecompressor(Configuration config, int bufferSize) {
    if (NativeCodeLoader.isNativeCodeLoaded()) {
      return new ZlibDecompressor(
          ZlibDecompressor.CompressionHeader.DEFAULT_HEADER, bufferSize);
    }
    // TODO buffer size for build-in zlib codec
    return ZlibFactory.getZlibDecompressor(config);
  }
}
