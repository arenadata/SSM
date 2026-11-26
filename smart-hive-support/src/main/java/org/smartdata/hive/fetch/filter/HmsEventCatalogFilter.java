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
import org.apache.hadoop.hive.metastore.utils.MetaStoreUtils;
import org.smartdata.hive.HiveSmartConf;
import org.smartdata.hive.fetch.HiveNotificationEvent;

/**
 * Accepts only events of the configured HMS catalog, since entities
 * are fetched only from this catalog during the HMS snapshot.
 */
@RequiredArgsConstructor
public class HmsEventCatalogFilter implements HmsEventFilter {
  private final String catalogName;

  @Override
  public boolean test(HiveNotificationEvent event) {
    // events without catalog are produced by HMS versions not supporting catalogs
    return event.getCatalogName() == null
        || catalogName.equalsIgnoreCase(event.getCatalogName());
  }

  public static HmsEventFilter fromConf(HiveSmartConf config) {
    return new HmsEventCatalogFilter(MetaStoreUtils.getDefaultCatalog(config));
  }
}
