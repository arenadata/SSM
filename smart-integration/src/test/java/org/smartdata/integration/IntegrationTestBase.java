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
package org.smartdata.integration;

import org.apache.hadoop.fs.Path;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.smartdata.SmartServiceState;
import org.smartdata.conf.SmartConf;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.integration.cluster.SmartCluster;
import org.smartdata.integration.cluster.SmartMiniCluster;
import org.smartdata.server.SmartServer;

import java.io.IOException;
import java.net.URL;
import java.time.Duration;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.function.Supplier;

public class IntegrationTestBase {

  protected SmartCluster cluster;
  protected SmartConf conf;
  protected SmartServer smartServer;

  @Before
  public void setup() throws Exception {
    // Set up an HDFS cluster
    cluster = new SmartMiniCluster();
    cluster.setUp();

    conf = cluster.getConf();
    conf.setLong(SmartConfKeys.SMART_STATUS_REPORT_PERIOD_KEY, 100);

    smartServer = SmartServer.launchWith(withSsmServerOptions(conf));
    waitTillSSMExitSafeMode();
  }

  public static <T> T retryUntil(
      Supplier<T> entitySupplier,
      Predicate<T> entityFinishPredicate,
      Duration interval,
      Duration timeout) {

    long totalWaitTimeout = timeout.toMillis();
    T entity;
    do {
      if (totalWaitTimeout <= 0) {
        Assert.fail("Timeout waiting for the predicate to happen");
      }

      try {
        Thread.sleep(interval.toMillis());
      } catch (InterruptedException exception) {
        // ignore
      }

      totalWaitTimeout -= interval.toMillis();

      entity = entitySupplier.get();
    } while (!entityFinishPredicate.test(entity));

    return entity;
  }

  protected void createFile(String path) {
    try {
      cluster.getFileSystem().createNewFile(new Path(path));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @After
  public void cleanUp() throws Exception {
    if (smartServer != null) {
      smartServer.shutdown();
    }
    if (cluster != null) {
      cluster.cleanUp();
    }
  }

  protected SmartConf withSsmServerOptions(SmartConf conf) {
    return conf;
  }

  private void waitTillSSMExitSafeMode() {
    retryUntil(
        () -> smartServer.getSSMServiceState(),
        state -> state != SmartServiceState.SAFEMODE,
        Duration.ofMillis(500),
        Duration.ofSeconds(5)
    );
  }

  public static String resourceAbsolutePath(String relativePath) {
    return Optional.ofNullable(
            IntegrationTestBase.class.getClassLoader().getResource(relativePath))
        .map(URL::getPath)
        .orElseThrow(() -> new RuntimeException("Resource not found"));
  }
}
