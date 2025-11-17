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
package org.smartdata.hive.util;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class DefaultTrieTest {
  private Trie<String, Boolean> trie;

  @Before
  public void init() {
    trie = new DefaultTrie<>();
  }

  @Test
  public void testPutIfNoIntersectingLocks() {
    boolean isNew = trie.putIfNoIntersectingLocks(key("test1"), true);
    assertTrue(isNew);

    isNew = trie.putIfNoIntersectingLocks(key("test1"), true);
    assertFalse(isNew);
    isNew = trie.putIfNoIntersectingLocks(key("test1"), false);
    assertFalse(isNew);

    isNew = trie.putIfNoIntersectingLocks(key("test1", "child"), true);
    assertFalse(isNew);
    isNew = trie.putIfNoIntersectingLocks(key("test1", "child2"), true);
    assertFalse(isNew);

    isNew = trie.putIfNoIntersectingLocks(key("parent2", "child"), true);
    assertTrue(isNew);
    isNew = trie.putIfNoIntersectingLocks(key("parent2", "child2"), true);
    assertTrue(isNew);
    isNew = trie.putIfNoIntersectingLocks(key("parent2", "child2"), true);
    assertFalse(isNew);

    isNew = trie.putIfNoIntersectingLocks(key("1", "2"), true);
    assertTrue(isNew);
    isNew = trie.putIfNoIntersectingLocks(key("1"), true);
    assertFalse(isNew);
  }

  @Test
  public void testGetPrefixValue() {
    trie.putIfNoIntersectingLocks(key("1"), true);

    assertTrue(trie.hasPrefixValues(key("1", "2", "3")));
    assertTrue(trie.hasPrefixValues(key("1", "2")));
    assertTrue(trie.hasPrefixValues(key("1")));

    trie.putIfNoIntersectingLocks(key("4", "5"), true);
    assertTrue(trie.hasPrefixValues(key("4", "5", "6", "7")));
    assertTrue(trie.hasPrefixValues(key("4", "5", "6")));
    assertTrue(trie.hasPrefixValues(key("4", "5")));

    assertFalse(trie.hasPrefixValues(key("4")));
    assertFalse(trie.hasPrefixValues(key("4", "another_key")));
    assertFalse(trie.hasPrefixValues(key("4", "another_key", "another_subkey")));
  }

  @Test
  public void testRemove() {
    trie.putIfNoIntersectingLocks(key("1", "2"), true);
    trie.putIfNoIntersectingLocks(key("1", "3"), true);

    boolean isRemoved = trie.remove(key("1", "2"));
    assertTrue(isRemoved);
    assertTrue(trie.hasPrefixValues(key("1", "3")));
    assertFalse(trie.hasPrefixValues(key("1", "2")));
    assertFalse(trie.hasPrefixValues(key("1", "2", "3")));
  }

  @Test
  public void testRemoveUnknownChild() {
    trie.putIfNoIntersectingLocks(key("1", "2"), true);

    boolean isRemoved = trie.remove(key("1", "2", "3"));

    assertFalse(isRemoved);
    assertTrue(trie.hasPrefixValues(key("1", "2")));
    assertTrue(trie.hasPrefixValues(key("1", "2", "3")));
  }

  @Test
  public void testRemoveUnknownParent() {
    trie.putIfNoIntersectingLocks(key("1", "2"), true);

    boolean isRemoved = trie.remove(key("1"));

    assertFalse(isRemoved);
    assertTrue(trie.hasPrefixValues(key("1", "2")));
    assertFalse(trie.hasPrefixValues(key("1")));
  }

  private Trie.Key<String> key(String... parts) {
    return new Trie.Key<>(parts);
  }
}