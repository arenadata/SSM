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


import lombok.Builder.Default;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.apache.hadoop.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.Consumer;

@RequiredArgsConstructor
@Builder
public class StreamCopyHandler {
  private final InputStream inputStream;

  private final OutputStream outputStream;

  @Default
  private final int bufferSize = 4096;

  @Default
  private final long offset = 0;

  @Default
  private final long count = -1;

  @Default
  private final boolean closeStreams = false;

  @Default
  private final Consumer<Float> progressConsumer = progress -> {};

  public static Builder of(InputStream inputStream, OutputStream outputStream) {
    return builder()
        .inputStream(inputStream)
        .outputStream(outputStream);
  }

  public void runCopy() throws IOException {
    byte[] buf = new byte[bufferSize];
    long bytesRemaining = count;
    int bytesRead;

    try {
      maybeSkip();

      while (bytesRemaining > 0) {
        int bytesToRead = (int) Math.min(bytesRemaining, bufferSize);

        bytesRead = inputStream.read(buf, 0, bytesToRead);
        if (bytesRead == -1) {
          break;
        }

        outputStream.write(buf, 0, bytesRead);
        bytesRemaining -= bytesRead;

        progressConsumer.accept(((float) (count - bytesRemaining)) / count);
      }
    } finally {
      if (closeStreams) {
        IOUtils.closeStream(outputStream);
        IOUtils.closeStream(inputStream);
      }
    }
  }

  private void maybeSkip() throws IOException {
    if (offset != 0) {
      inputStream.skip(offset);
    }
  }
}
