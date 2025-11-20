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
package org.smartdata.hive.fetch.filter;

import lombok.RequiredArgsConstructor;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.smartdata.hive.fetch.HiveNotificationEvent;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public abstract class HmsEventNameFilterBaseTest {
  @Parameterized.Parameter
  public List<String> patterns;
  @Parameterized.Parameter(1)
  public String inputString;
  @Parameterized.Parameter(2)
  public boolean expectedResult;

  @Test
  public void testInputValue() {
    HmsEventFilter filter = buildFilter(patterns);
    HiveNotificationEvent event = HiveNotificationEvent.builder()
        .fullName(inputString)
        .build();
    boolean actualResult = filter.test(event);
    assertEquals(expectedResult, actualResult);
  }

  protected abstract HmsEventFilter buildFilter(List<String> patterns);

  @RequiredArgsConstructor
  static class Parameters {
    protected final List<String> patterns;
    protected String inputString = "";
    protected boolean expectedResult;

    public static Parameters patterns(String... templates) {
      return new Parameters(Arrays.asList(templates));
    }

    public Object[] shouldIgnore(String inputString) {
      this.inputString = inputString;
      this.expectedResult = false;
      return asJunitParameters();
    }

    public Object[] shouldAccept(String inputString) {
      this.inputString = inputString;
      this.expectedResult = true;
      return asJunitParameters();
    }

    protected Object[] asJunitParameters() {
      return new Object[]{patterns, inputString, expectedResult};
    }
  }
}