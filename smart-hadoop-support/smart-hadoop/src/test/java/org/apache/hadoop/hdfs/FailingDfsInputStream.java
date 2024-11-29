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

import java.io.IOException;

public class FailingDfsInputStream extends DFSInputStream {

  private final boolean shouldFail;

  private int bytesToReadBeforeFail;
  private boolean firstBytesRead;

  public FailingDfsInputStream(DFSInputStream wrapped,
                               boolean shouldFail,
                               int readBytesBeforeFail) throws IOException {
    super(wrapped.dfsClient, wrapped.src, wrapped.verifyChecksum, wrapped.getLocatedBlocks());

    this.shouldFail = shouldFail;
    this.bytesToReadBeforeFail = readBytesBeforeFail;
  }

  public int read(byte[] buff, int off, int len) throws IOException {
    if (!shouldFail) {
      return super.read(buff, off, len);
    }
    if (firstBytesRead) {
      throw new IOException("Some error");
    }
    if (len < bytesToReadBeforeFail) {
      bytesToReadBeforeFail -= len;
      return super.read(buff, off, len);
    }

    firstBytesRead = true;
    super.read(buff, off, bytesToReadBeforeFail);
    return bytesToReadBeforeFail;
  }
}
