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
  public void testPutIfNoPrefixPresent() {
    boolean isNew = trie.putIfNoPrefixPresent(key("test1"), true);
    assertTrue(isNew);

    isNew = trie.putIfNoPrefixPresent(key("test1"), true);
    assertFalse(isNew);
    isNew = trie.putIfNoPrefixPresent(key("test1"), false);
    assertFalse(isNew);

    isNew = trie.putIfNoPrefixPresent(key("test1", "child"), true);
    assertFalse(isNew);
    isNew = trie.putIfNoPrefixPresent(key("test1", "child2"), true);
    assertFalse(isNew);

    isNew = trie.putIfNoPrefixPresent(key("parent2", "child"), true);
    assertTrue(isNew);
    isNew = trie.putIfNoPrefixPresent(key("parent2", "child2"), true);
    assertTrue(isNew);
    isNew = trie.putIfNoPrefixPresent(key("parent2", "child2"), true);
    assertFalse(isNew);

    isNew = trie.putIfNoPrefixPresent(key("1", "2"), true);
    assertTrue(isNew);
    isNew = trie.putIfNoPrefixPresent(key("1"), true);
    assertTrue(isNew);
  }

  @Test
  public void testHasPrefixValues() {
    trie.putIfNoPrefixPresent(key("1"), true);

    assertTrue(trie.hasPrefixValues(key("1", "2", "3")));
    assertTrue(trie.hasPrefixValues(key("1", "2")));
    assertTrue(trie.hasPrefixValues(key("1")));

    trie.putIfNoPrefixPresent(key("4", "5"), true);
    assertTrue(trie.hasPrefixValues(key("4", "5", "6", "7")));
    assertTrue(trie.hasPrefixValues(key("4", "5", "6")));
    assertTrue(trie.hasPrefixValues(key("4", "5")));

    assertFalse(trie.hasPrefixValues(key("4")));
    assertFalse(trie.hasPrefixValues(key("4", "another_key")));
    assertFalse(trie.hasPrefixValues(key("4", "another_key", "another_subkey")));

    trie.putIfNoPrefixPresent(key("8", "9"), true);
    trie.putIfNoPrefixPresent(key("8"), true);
    assertTrue(trie.hasPrefixValues(key("8")));
    assertTrue(trie.hasPrefixValues(key("8", "9")));
  }

  @Test
  public void testRemove() {
    trie.putIfNoPrefixPresent(key("1", "2"), true);

    boolean isRemoved = trie.remove(key("1", "2"));
    assertTrue(isRemoved);
    assertFalse(trie.hasPrefixValues(key("1", "2")));
    assertFalse(trie.hasPrefixValues(key("1", "2", "3")));
  }

  @Test
  public void testRemoveUnknownChild() {
    trie.putIfNoPrefixPresent(key("1", "2"), true);

    boolean isRemoved = trie.remove(key("1", "2", "3"));

    assertFalse(isRemoved);
    assertTrue(trie.hasPrefixValues(key("1", "2")));
    assertTrue(trie.hasPrefixValues(key("1", "2", "3")));
  }

  @Test
  public void testRemoveUnknownParent() {
    trie.putIfNoPrefixPresent(key("1", "2"), true);

    boolean isRemoved = trie.remove(key("1"));

    assertFalse(isRemoved);
    assertTrue(trie.hasPrefixValues(key("1", "2")));
    assertFalse(trie.hasPrefixValues(key("1")));
  }

  @Test
  public void testRemoveChild() {
    trie.putIfNoPrefixPresent(key("8", "9"), true);
    trie.putIfNoPrefixPresent(key("8"), true);

    boolean isRemoved = trie.remove(key("8", "9"));

    assertTrue(isRemoved);
    assertTrue(trie.hasPrefixValues(key("8", "9")));
    assertTrue(trie.hasPrefixValues(key("8")));
  }

  @Test
  public void testRemoveParent() {
    trie.putIfNoPrefixPresent(key("5", "6"), true);
    trie.putIfNoPrefixPresent(key("5"), true);

    boolean isRemoved = trie.remove(key("5"));

    assertTrue(isRemoved);
    assertTrue(trie.hasPrefixValues(key("5", "6")));
    assertFalse(trie.hasPrefixValues(key("5")));
  }

  private Trie.Key<String> key(String... parts) {
    return new Trie.Key<>(parts);
  }
}