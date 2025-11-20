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

import org.apache.hadoop.conf.Configuration;
import org.junit.Test;
import org.junit.runners.Parameterized;
import org.smartdata.hive.HiveSmartConf;

import java.util.List;
import java.util.Optional;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.smartdata.hive.HiveSmartConf.HMS_EVENT_INCLUDE_PATTERNS;
import static org.smartdata.hive.fetch.filter.HmsEventNameFilterBaseTest.Parameters.patterns;

public class HmsEventNameIncludeFilterTest extends HmsEventNameFilterBaseTest {
  @Parameterized.Parameters(
      name = "patterns = {0}, inputString = {1}, expectedResult = {2}")
  public static Object[] parameters() {
    return new Object[][]{
        patterns("include.*").shouldAccept("include"),
        patterns("include.*").shouldAccept("include.tb1"),
        patterns("include.*").shouldAccept("included.tb1"),
        patterns("include.*").shouldAccept("include.include"),
        patterns("include.*").shouldIgnore("includ"),
        patterns("include.*").shouldIgnore("includ.tb"),
        patterns("include.*").shouldIgnore("another_db"),

        patterns(".*include.*").shouldAccept("db.include"),
        patterns(".*include.*").shouldAccept("db.included"),
        patterns(".*include.*").shouldAccept("include"),
        patterns(".*include.*").shouldAccept("include.tb1"),
        patterns(".*include.*").shouldAccept("db.tb.included_partition"),
        patterns(".*include.*").shouldIgnore("another_db.includ"),
        patterns(".*include.*").shouldIgnore("ignor.tb"),
        patterns(".*include.*").shouldIgnore("another_db"),
        patterns(".*include.*").shouldIgnore("another_db.includ"),

        patterns("db1.*tbl.*", ".*db2.*").shouldAccept("db1.tbl1"),
        patterns("db1.*tbl.*", ".*db2.*").shouldAccept("db2"),
        patterns("db1.*tbl.*", ".*db2.*").shouldAccept("other.db2.t1"),
        patterns("db1.*tbl.*", ".*db2.*").shouldIgnore("db3"),
        patterns("db1.*tbl.*", ".*db2.*").shouldIgnore("db3.t1"),
        patterns("db1.*tbl.*", ".*db2.*").shouldIgnore("db1"),
    };
  }

  @Test
  public void testBuildFilterFromConfig() {
    Configuration configuration = new Configuration();
    configuration.set(HMS_EVENT_INCLUDE_PATTERNS, ".*ignore.*,db1.*");
    Optional<HmsEventFilter> hmsEventFilter = HmsEventNameIncludeFilter.fromConf(
        new HiveSmartConf(configuration));

    assertTrue(hmsEventFilter.isPresent());
  }

  @Test
  public void testNoOpFilterFromConfig() {
    Configuration configuration = new Configuration();
    Optional<HmsEventFilter> hmsEventFilter = HmsEventNameIncludeFilter.fromConf(
        new HiveSmartConf(configuration));

    assertFalse(hmsEventFilter.isPresent());
  }


  @Override
  protected HmsEventFilter buildFilter(List<String> patterns) {
    return new HmsEventNameIncludeFilter(patterns);
  }
}