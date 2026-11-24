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
import org.apache.hadoop.hive.metastore.conf.MetastoreConf;
import org.junit.Test;
import org.smartdata.hive.HiveSmartConf;
import org.smartdata.hive.fetch.HiveNotificationEvent;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class HmsEventCatalogFilterTest {
  @Test
  public void testAcceptEventsOfDefaultCatalog() {
    HmsEventFilter filter = HmsEventCatalogFilter.fromConf(
        new HiveSmartConf(new Configuration()));

    assertTrue(filter.test(eventWithCatalog("hive")));
    assertTrue(filter.test(eventWithCatalog("HIVE")));
    assertFalse(filter.test(eventWithCatalog("spark")));
  }

  @Test
  public void testAcceptEventsOfConfiguredCatalog() {
    Configuration configuration = new Configuration();
    MetastoreConf.setVar(configuration, MetastoreConf.ConfVars.CATALOG_DEFAULT, "spark");
    HmsEventFilter filter = HmsEventCatalogFilter.fromConf(
        new HiveSmartConf(configuration));

    assertTrue(filter.test(eventWithCatalog("spark")));
    assertFalse(filter.test(eventWithCatalog("hive")));
  }

  @Test
  public void testAcceptEventsWithoutCatalog() {
    HmsEventFilter filter = new HmsEventCatalogFilter("hive");

    assertTrue(filter.test(eventWithCatalog(null)));
  }

  private HiveNotificationEvent eventWithCatalog(String catalogName) {
    return HiveNotificationEvent.builder()
        .catalogName(catalogName)
        .fullName("db.tbl")
        .build();
  }
}
