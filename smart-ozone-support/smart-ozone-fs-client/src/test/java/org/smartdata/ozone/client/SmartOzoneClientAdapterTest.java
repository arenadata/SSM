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
package org.smartdata.ozone.client;

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.ozone.OzoneClientAdapter;
import org.junit.Before;
import org.junit.Test;
import org.smartdata.metrics.FileAccessEvent;
import org.smartdata.model.FileState;
import org.smartdata.protocol.SmartClientProtocol;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

public class SmartOzoneClientAdapterTest {

  private OzoneClientAdapter delegate;
  private MockSsmClient ssmClient;

  @Before
  public void initMocks() {
    this.delegate = mock(OzoneClientAdapter.class);
    this.ssmClient = new MockSsmClient();
  }

  @Test
  public void testReportAccessEventOfs() throws IOException {
    testReportAccessEventInternal();
  }

  @Test
  public void testReportAccessEventO3fs() throws IOException {
    testReportAccessEventInternal("someVolume", "someBucket");
  }

  public void testReportAccessEventInternal(String... basePathSegments) throws IOException {
    SmartOzoneClientAdapter ssmOzoneClient = new SmartOzoneClientAdapter(
        delegate, ssmClient, basePathSegments);

    ssmOzoneClient.createFile("key", (short) 1, false, false);
    assertTrue(ssmClient.accessEvents.isEmpty());

    ssmOzoneClient.getFileStatus("key1", null, null, null);
    assertTrue(ssmClient.accessEvents.isEmpty());

    ssmOzoneClient.readFile("someKey");
    assertEquals(1, ssmClient.accessEvents.size());

    ssmOzoneClient.readFile("someDir/anotherKey");
    assertEquals(2, ssmClient.accessEvents.size());

    List<String> actualAccessedFiles = ssmClient.accessEvents.stream()
        .map(FileAccessEvent::getPath)
        .collect(Collectors.toList());

    List<String> expectedAccessFiles = Stream.of("someKey", "someDir/anotherKey")
        .map(path -> new Path(ssmOzoneClient.getBasePath(), path))
        .map(path -> path.toUri().getPath())
        .collect(Collectors.toList());

    assertEquals(expectedAccessFiles, actualAccessedFiles);
  }

  private static class MockSsmClient implements SmartClientProtocol {

    private final List<FileAccessEvent> accessEvents = new ArrayList<>();

    @Override
    public void reportFileAccessEvent(FileAccessEvent event) {
      accessEvents.add(event);
    }

    @Override
    public FileState getFileState(String filePath) {
      return null;
    }
  }
}