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
package org.smartdata.test.util.comparator;

import java.time.LocalDateTime;
import java.util.Comparator;

import static org.smartdata.test.util.constant.CommonConstants.DATE_TIME_FORMATTER_UI;


public class UiDateTimeComparator implements Comparator<String> {

  @Override
  public int compare(String o1, String o2) {
    if (o1 == null || o2 == null) {
      throw new IllegalArgumentException("Arguments must not be null");
    }
    LocalDateTime localDateTime1 = LocalDateTime.parse(o1, DATE_TIME_FORMATTER_UI);
    LocalDateTime localDateTime2 = LocalDateTime.parse(o2, DATE_TIME_FORMATTER_UI);
    return localDateTime1.compareTo(localDateTime2);
  }
}
