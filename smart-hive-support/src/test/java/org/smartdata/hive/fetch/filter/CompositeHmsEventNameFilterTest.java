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
import org.apache.hadoop.conf.Configuration;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.smartdata.hive.HiveSmartConf;
import org.smartdata.hive.fetch.HiveNotificationEvent;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.smartdata.hive.HiveSmartConf.HMS_EVENT_IGNORE_PATTERNS;
import static org.smartdata.hive.HiveSmartConf.HMS_EVENT_INCLUDE_PATTERNS;
import static org.smartdata.hive.fetch.filter.HmsEventFilter.NO_OP_FILTER;

@RunWith(Parameterized.class)
public class CompositeHmsEventNameFilterTest {
  @Parameterized.Parameter
  public String inputString;
  @Parameterized.Parameter(1)
  public boolean expectedResult;

  @Parameterized.Parameters(
      name = "inputString = {0}, expectedResult = {1}")
  public static Object[] parameters() {
    return new Object[][]{
        {"include", true},
        {"include1", true},
        {"3.include1", true},
        {"include.ignore", false},
        {"another", false},
        {"another.ignore", false},
        {"another.ignored", false},
        {"another.include.", true},
    };
  }

  @Test
  public void testInputValue() {
    HiveNotificationEvent event = HiveNotificationEvent.builder()
        .fullName(inputString)
        .build();
    boolean actualResult = buildFilter().test(event);
    assertEquals(expectedResult, actualResult);
  }

  @Test
  public void testBuildFilterFromConf() {
    Configuration configuration = new Configuration();
    configuration.set(HMS_EVENT_IGNORE_PATTERNS, ".*ignore.*,db1.*");
    configuration.set(HMS_EVENT_INCLUDE_PATTERNS, ".*include.*,db1.*");
    HmsEventFilter filter = CompositeHmsEventFilter.fromConf(
        new HiveSmartConf(configuration));

    assertTrue(filter instanceof CompositeHmsEventFilter);
    CompositeHmsEventFilter compositeFilter = (CompositeHmsEventFilter) filter;
    assertEquals(2, compositeFilter.getDelegates().size());
  }

  @Test
  public void testUnwrapIgnoreFilter() {
    Configuration configuration = new Configuration();
    configuration.set(HMS_EVENT_IGNORE_PATTERNS, ".*ignore.*,db1.*");
    HmsEventFilter filter = CompositeHmsEventFilter.fromConf(
        new HiveSmartConf(configuration));

    assertTrue(filter instanceof HmsEventNameIgnoreFilter);
  }

  @Test
  public void testUnwrapIncludeFilter() {
    Configuration configuration = new Configuration();
    configuration.set(HMS_EVENT_INCLUDE_PATTERNS, ".*include.*,db1.*");
    HmsEventFilter filter = CompositeHmsEventFilter.fromConf(
        new HiveSmartConf(configuration));

    assertTrue(filter instanceof HmsEventNameIncludeFilter);
  }

  @Test
  public void testNoOpFilterFromConfig() {
    Configuration configuration = new Configuration();
    HmsEventFilter filter = CompositeHmsEventFilter.fromConf(
        new HiveSmartConf(configuration));

    assertEquals(NO_OP_FILTER, filter);
  }

  protected HmsEventFilter buildFilter() {
    List<HmsEventFilter> filters = Arrays.asList(
        new NameContainsFilter("include"),
        new NameNotContainsFilter("ignore")
    );
    return new CompositeHmsEventFilter(filters);
  }

  @RequiredArgsConstructor
  private static class NameContainsFilter implements HmsEventFilter {

    private final String value;

    @Override
    public boolean test(HiveNotificationEvent event) {
      return event.getFullName().contains(value);
    }
  }

  @RequiredArgsConstructor
  private static class NameNotContainsFilter implements HmsEventFilter {

    private final String value;

    @Override
    public boolean test(HiveNotificationEvent event) {
      return !event.getFullName().contains(value);
    }
  }
}