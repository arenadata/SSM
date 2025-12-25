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
package org.smartdata.ozone;

import org.apache.hadoop.hdds.client.ReplicationConfig;
import org.apache.hadoop.hdds.client.ReplicationFactor;
import org.apache.hadoop.hdds.client.ReplicationType;
import org.apache.hadoop.ozone.client.ObjectStore;
import org.apache.hadoop.ozone.client.OzoneBucket;
import org.apache.hadoop.ozone.client.OzoneClientFactory;
import org.apache.hadoop.ozone.client.io.OzoneOutputStream;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.smartdata.conf.SmartConf;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Optional;

import static org.apache.hadoop.fs.FileSystem.FS_DEFAULT_NAME_KEY;

public class OzoneClusterHarness {

  private static final ReplicationConfig REPLICATION_CONFIG =
      ReplicationConfig.fromTypeAndFactor(ReplicationType.RATIS, ReplicationFactor.ONE);

  @Rule
  public OzoneClusterCompose ozoneContainer = new OzoneClusterCompose();

  protected OzoneSmartConf ozoneConf;
  protected ObjectStore ozoneClient;

  @Before
  public void init() throws Exception {
    SmartConf smartConf = new SmartConf();
    smartConf.set("ozone.om.address", ozoneContainer.getOmRpcAddress());
    smartConf.set(FS_DEFAULT_NAME_KEY, "ofs://" + ozoneContainer.getOmRpcAddress());

    ozoneConf = new OzoneSmartConf(smartConf);
    ozoneClient = OzoneClientFactory.getRpcClient(ozoneConf).getObjectStore();
  }

  @After
  public void tearDown() throws IOException {
    ozoneClient.getClientProxy().close();
  }

  public static void createKey(OzoneBucket bucket, String key, String data) throws IOException {
    byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
    try (OzoneOutputStream outputStream =
             bucket.createKey(key, dataBytes.length, REPLICATION_CONFIG, new HashMap<>())) {
      outputStream.write(dataBytes);
      outputStream.flush();
    }
  }

  public static String resourceAbsolutePath(String relativePath) {
    return Optional.ofNullable(
            OzoneClusterHarness.class.getClassLoader().getResource(relativePath))
        .map(URL::getPath)
        .orElseThrow(() -> new RuntimeException("Resource not found"));
  }
}
