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
import org.junit.Before;
import org.junit.Test;
import org.smartdata.metrics.FileAccessEvent;
import org.smartdata.model.FileState;
import org.smartdata.ozone.OzoneClusterHarness;
import org.smartdata.ozone.client.SmartOzoneClientAdapter;
import org.smartdata.protocol.SmartClientProtocol;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SmartOzoneClientAdapterTest extends OzoneClusterHarness {
  private static final String TEST_VOLUME = "vol1";
  private static final String TEST_BUCKET = "buck1";

  private static final String TEST_DATA = "data_777";

  private MockSsmClient ssmClient;

  @Before
  public void initClient() throws IOException {
    this.ssmClient = new MockSsmClient();

    ozoneClient.createVolume(TEST_VOLUME);
    ozoneClient.getVolume(TEST_VOLUME)
        .createBucket(TEST_BUCKET);
  }

  @Test
  public void testReportAccessEventOfs() throws Exception {
    SmartOzoneClientAdapter clientAdapter = new SmartRootedOzoneFileSystem.SmartClientAdapter(
        ozoneContainer.getOmHost(), ozoneContainer.getOmPort(),
        ozoneConf, null, ssmClient);
    testReportAccessEventInternal(clientAdapter, TEST_VOLUME, TEST_BUCKET);
  }

  @Test
  public void testReportAccessEventO3fs() throws Exception {
    SmartOzoneClientAdapter clientAdapter = new SmartOzoneFileSystem.SmartClientAdapter(
        ozoneContainer.getOmHost(), ozoneContainer.getOmPort(),
        ozoneConf, TEST_VOLUME, TEST_BUCKET, null, ssmClient);
    testReportAccessEventInternal(clientAdapter);
  }

  private void testReportAccessEventInternal(SmartOzoneClientAdapter clientAdapter, String... prefixSegments)
      throws Exception {
    String keyPrefix = Arrays.stream(prefixSegments)
        .collect(Collectors.joining("/", "", "/"));

    createFile(clientAdapter, keyPrefix + "key");
    createFile(clientAdapter, keyPrefix + "anotherKey");
    createFile(clientAdapter, keyPrefix + "keyToRemove");
    assertTrue(ssmClient.accessEvents.isEmpty());

    clientAdapter.getFileStatus(keyPrefix + "anotherKey",
        new URI("ofs://test:7070"), new Path(keyPrefix, "anotherKey"), "anon");
    assertTrue(ssmClient.accessEvents.isEmpty());

    clientAdapter.deleteObject(keyPrefix + "keyToRemove");
    assertTrue(ssmClient.accessEvents.isEmpty());

    clientAdapter.readFile(keyPrefix + "key").close();
    assertEquals(1, ssmClient.accessEvents.size());

    clientAdapter.readFile(keyPrefix + "anotherKey").close();
    assertEquals(2, ssmClient.accessEvents.size());

    List<String> actualAccessedFiles = ssmClient.accessEvents.stream()
        .map(FileAccessEvent::getPath)
        .collect(Collectors.toList());

    List<String> expectedAccessFiles = Stream.of("key", "anotherKey")
        .map(path -> new Path(new Path("/" + TEST_VOLUME, TEST_BUCKET), path))
        .map(path -> path.toUri().getPath())
        .collect(Collectors.toList());

    assertEquals(expectedAccessFiles, actualAccessedFiles);
  }

  private void createFile(SmartOzoneClientAdapter clientAdapter, String key) throws IOException {
    try (OzoneFSOutputStream outputStream = clientAdapter.createFile(key, (short) 1, true, true)) {
      outputStream.write(TEST_DATA.getBytes(StandardCharsets.UTF_8));
      outputStream.flush();
    }
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