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
package org.smartdata.ozone.handler;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.smartdata.ozone.model.FsObjectStreamRecord;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;

@RequiredArgsConstructor
@Slf4j
public class AsyncFsObjectStreamHandler implements FsObjectStreamHandler {
  private final FsObjectHandler delegate;
  private final ExecutorService executorService;

  @Override
  public void collectAsync(BlockingQueue<FsObjectStreamRecord> objectStream) {
    executorService.execute(() -> collect(objectStream, delegate));
  }

  private void collect(
      BlockingQueue<FsObjectStreamRecord> resourceStream,
      FsObjectHandler recordHandler
  ) {
    FsObjectStreamRecord event = null;

    while (event == null || !event.isLastRecord()) {
      try {
        event = resourceStream.take();
        recordHandler.handle(event);
      } catch (Exception exception) {
        log.error("Error handling event", exception);
        close();
        throw new RuntimeException(exception);
      }
    }
  }

  @Override
  public void close() {
    executorService.shutdown();
  }
}
