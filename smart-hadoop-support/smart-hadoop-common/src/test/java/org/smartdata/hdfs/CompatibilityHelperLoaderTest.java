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

import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class CompatibilityHelperLoaderTest {

  @Test
  public void throwOnWrongVersionFormat() {
    IllegalArgumentException exception = Assert.assertThrows(
        IllegalArgumentException.class,
        () -> CompatibilityHelperLoader.createCompatibilityHelper("v1"));

    assertTrue(exception.getMessage().contains(
        "Illegal Hadoop Version, expected 'Major.Minor.*' format"));
  }

  @Test
  public void throwOnUnsupportedMajorVersion() {
    IllegalArgumentException exception = Assert.assertThrows(
        IllegalArgumentException.class,
        () -> CompatibilityHelperLoader.createCompatibilityHelper("2.10.1"));

    assertTrue(exception.getMessage().contains(
        "Hadoop versions below 3.2.X are not supported"));
  }

  @Test
  public void throwOnUnsupportedMinorVersion() {
    IllegalArgumentException exception = Assert.assertThrows(
        IllegalArgumentException.class,
        () -> CompatibilityHelperLoader.createCompatibilityHelper("3.1.12"));

    assertTrue(exception.getMessage().contains(
        "Hadoop versions below 3.2.X are not supported"));
  }
}
