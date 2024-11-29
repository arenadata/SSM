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

import org.testcontainers.containers.MinIOContainer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class SmartMinIOContainer extends MinIOContainer {
  private static final int MINIO_UI_PORT = 9001;

  private List<String> buckets;

  public SmartMinIOContainer(String dockerImageName) {
    super(dockerImageName);
    this.buckets = new ArrayList<>();
  }

  public SmartMinIOContainer withBuckets(String... buckets) {
    this.buckets = Arrays.asList(buckets);
    return this;
  }

  @Override
  public void configure() {
    super.configure();

    if (buckets.isEmpty()) {
      return;
    }

    withCreateContainerCmdModifier(cmd -> {
      cmd.withEntrypoint("sh");
      cmd.withCmd("-c", createCmd());
    });
  }

  @Override
  public SmartMinIOContainer withPassword(String password) {
    return (SmartMinIOContainer) super.withPassword(password);
  }

  @Override
  public SmartMinIOContainer withUserName(String userName) {
    return (SmartMinIOContainer) super.withUserName(userName);
  }

  private String createBucketDirs() {
    return buckets.stream()
        .map(bucket -> "/tmp/buckets/" + bucket)
        .collect(Collectors.joining(" "));
  }

  private String createCmd() {
    return "mkdir -p " + createBucketDirs()
        + " && /usr/bin/docker-entrypoint.sh minio server "
        + "--console-address :" + MINIO_UI_PORT
        + " /tmp/buckets";
  }
}
