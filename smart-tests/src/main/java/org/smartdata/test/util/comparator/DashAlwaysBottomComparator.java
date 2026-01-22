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

import lombok.NonNull;
import org.jetbrains.annotations.NotNull;

import java.util.Comparator;

public class DashAlwaysBottomComparator implements Comparator<String> {
  private static final String DASH = "-";
  private final Comparator<String> additionalComparator;

  public DashAlwaysBottomComparator() {
    this(Comparator.naturalOrder());
  }

  public DashAlwaysBottomComparator(Comparator<String> additionalComparator) {
    this.additionalComparator = additionalComparator;
  }

  @Override
  public int compare(@NonNull String o1, @NonNull String o2) {
    boolean o1IsDash = DASH.equals(o1);
    boolean o2IsDash = DASH.equals(o2);
    if (o1IsDash && o2IsDash) {
      return 0;
    }
    if (o1IsDash) {
      return 1;
    }
    if (o2IsDash) {
      return -1;
    }
    return additionalComparator.compare(o1, o2);
  }

  @Override
  public @NotNull Comparator<String> reversed() {
    return new DashAlwaysBottomComparator(additionalComparator.reversed());
  }
}
