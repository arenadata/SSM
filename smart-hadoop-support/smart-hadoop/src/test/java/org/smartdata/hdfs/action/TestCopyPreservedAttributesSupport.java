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
package org.smartdata.hdfs.action;

import org.junit.Test;
import org.smartdata.model.PreserveAttribute;

import java.io.PrintStream;
import java.util.EnumSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.smartdata.hdfs.action.CopyPreservedAttributesSupport.PRESERVE_ARG;
import static org.smartdata.hdfs.action.CopyPreservedAttributesSupport.PRESERVE_NONE;
import static org.smartdata.hdfs.action.CopyPreservedAttributesSupport.parsePreserveAttributes;
import static org.smartdata.model.PreserveAttribute.GROUP;
import static org.smartdata.model.PreserveAttribute.MODIFICATION_TIME;
import static org.smartdata.model.PreserveAttribute.OWNER;
import static org.smartdata.model.PreserveAttribute.PERMISSIONS;
import static org.smartdata.model.PreserveAttribute.REPLICATION_NUMBER;

public class TestCopyPreservedAttributesSupport {
  private static final Set<PreserveAttribute> DEFAULT_ATTRIBUTES =
      EnumSet.of(OWNER, GROUP, PERMISSIONS);

  private final CopyPreservedAttributesSupport support =
      new CopyPreservedAttributesSupport(DEFAULT_ATTRIBUTES, new PrintStream(System.out));

  @Test
  public void testGetPreserveAttributes() {
    assertEquals(DEFAULT_ATTRIBUTES, support.getPreserveAttributes(Map.of()));
    assertEquals(EnumSet.of(OWNER),
        support.getPreserveAttributes(Map.of(PRESERVE_ARG, "owner")));
    assertEquals(EnumSet.of(PERMISSIONS, REPLICATION_NUMBER),
        support.getPreserveAttributes(Map.of(PRESERVE_ARG, "permissions,replication")));
    assertEquals(Set.of(),
        support.getPreserveAttributes(Map.of(PRESERVE_ARG, PRESERVE_NONE)));
  }

  @Test
  public void testParseAttributes() {
    assertEquals(Optional.of(EnumSet.of(OWNER, GROUP)), parsePreserveAttributes("owner,group"));
    assertEquals(Optional.of(EnumSet.of(OWNER, MODIFICATION_TIME)),
        parsePreserveAttributes(" OWNER , Modification-Time "));
  }

  @Test
  public void testParseNoneOption() {
    assertEquals(Optional.of(Set.of()), parsePreserveAttributes("none"));
    assertEquals(Optional.of(Set.of()), parsePreserveAttributes(" NONE "));
  }

  @Test
  public void testParseMissingAttributes() {
    // default attributes should be preserved
    assertEquals(Optional.empty(), parsePreserveAttributes(null));
    assertEquals(Optional.empty(), parsePreserveAttributes(" "));
    assertEquals(Optional.empty(), parsePreserveAttributes(" , "));
  }

  @Test
  public void testParseInvalidAttributes() {
    assertThrows(IllegalArgumentException.class, () -> parsePreserveAttributes("owner,unknown"));
    assertThrows(IllegalArgumentException.class, () -> parsePreserveAttributes("owner,none"));
  }
}
