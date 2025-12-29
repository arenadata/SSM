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
package org.apache.hadoop.fs.ozone;

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.smartdata.metrics.FileAccessEvent;
import org.smartdata.model.FileState;
import org.smartdata.ozone.client.SmartOzoneClientAdapter;
import org.smartdata.protocol.SmartClientProtocol;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SmartOzoneClientAdapterTest {

  private MockSsmClient ssmClient;

  @Before
  public void init() {
    this.ssmClient = new MockSsmClient();
  }

  @Test
  @Ignore("Unignore when testing environment for Ozone will be added (ADH-7291)")
  public void testReportAccessEventOfs() throws IOException {
    SmartOzoneClientAdapter clientAdapter = new SmartRootedOzoneFileSystem.SmartClientAdapter(
        "TODO", -1, new OzoneConfiguration(), null, ssmClient);
    testReportAccessEventInternal(clientAdapter);
  }

  @Test
  @Ignore("Unignore when testing environment for Ozone will be added (ADH-7291)")
  public void testReportAccessEventO3fs() throws IOException {
    SmartOzoneClientAdapter clientAdapter = new SmartOzoneFileSystem.SmartClientAdapter(
        "TODO", -1, new OzoneConfiguration(), "someVolume", "someBucket", null, ssmClient);
    testReportAccessEventInternal(clientAdapter);
  }

  public void testReportAccessEventInternal(SmartOzoneClientAdapter clientAdapter) throws IOException {
    clientAdapter.createFile("key", (short) 1, false, false);
    assertTrue(ssmClient.accessEvents.isEmpty());

    clientAdapter.getFileStatus("key1", null, null, null);
    assertTrue(ssmClient.accessEvents.isEmpty());

    clientAdapter.readFile("someKey");
    assertEquals(1, ssmClient.accessEvents.size());

    clientAdapter.readFile("someDir/anotherKey");
    assertEquals(2, ssmClient.accessEvents.size());

    List<String> actualAccessedFiles = ssmClient.accessEvents.stream()
        .map(FileAccessEvent::getPath)
        .collect(Collectors.toList());

    List<String> expectedAccessFiles = Stream.of("someKey", "someDir/anotherKey")
        .map(path -> new Path(clientAdapter.getBasePath(), path))
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