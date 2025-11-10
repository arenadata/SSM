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
package org.smartdata.client.activeserver;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.stream.IntStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ActiveServerAddressFileCacheTest {

  @Rule
  public TemporaryFolder folder = new TemporaryFolder();

  @Test
  public void testPutReadAddress() throws IOException {
    File cacheFile = folder.newFile("testFile");

    ActiveServerAddressFileCache fileCache =
        new ActiveServerAddressFileCache(Paths.get(cacheFile.toURI()));

    InetSocketAddress expectedAddress =
        InetSocketAddress.createUnresolved("unresolved", 81);

    fileCache.put(expectedAddress);
    Optional<InetSocketAddress> actualAddress = fileCache.get();

    assertTrue(actualAddress.isPresent());
    assertEquals(expectedAddress, actualAddress.get());
  }

  @Test
  public void testOverwriteAddress() throws IOException {
    File cacheFile = folder.newFile("overwriteFile");

    ActiveServerAddressFileCache fileCache =
        new ActiveServerAddressFileCache(Paths.get(cacheFile.toURI()));

    InetSocketAddress expectedAddress =
        InetSocketAddress.createUnresolved("host", 9);

    IntStream.range(0, 10)
        .mapToObj(port -> InetSocketAddress.createUnresolved("host", port))
        .forEach(fileCache::put);

    Optional<InetSocketAddress> actualAddress = fileCache.get();

    assertTrue(actualAddress.isPresent());
    assertEquals(expectedAddress, actualAddress.get());
  }

  @Test
  public void testReturnEmptyAddressIfFileNotFound() throws IOException {
    File cacheFile = folder.newFile("anotherFile");

    ActiveServerAddressFileCache fileCache =
        new ActiveServerAddressFileCache(Paths.get(cacheFile.toURI()));

    Optional<InetSocketAddress> actualAddress = fileCache.get();

    assertFalse(actualAddress.isPresent());
  }

  @Test
  public void testReturnEmptyAddressIfFileIsCorrupt() throws IOException {
    File cacheFile = folder.newFile("corruptFile");
    Path cacheFilePath = Paths.get(cacheFile.toURI());

    Files.write(cacheFilePath, "blabla".getBytes(StandardCharsets.UTF_8));

    ActiveServerAddressFileCache fileCache =
        new ActiveServerAddressFileCache(cacheFilePath);

    Optional<InetSocketAddress> actualAddress = fileCache.get();

    assertFalse(actualAddress.isPresent());
  }
}
