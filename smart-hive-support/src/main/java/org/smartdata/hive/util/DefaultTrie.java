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

import lombok.RequiredArgsConstructor;

import java.util.Optional;

@RequiredArgsConstructor
public class DefaultTrie<K, V> implements Trie<K, V> {
  private final DefaultTrieNode<K, V> root;

  public DefaultTrie() {
    this.root = new DefaultTrieNode<>(null, null);
  }

  @Override
  public boolean hasPrefixValues(Key<K> key) {
    DefaultTrieNode<K, V> iter = root;
    for (K segment : key.getSegments()) {
      Optional<DefaultTrieNode<K, V>> child = iter.getChild(segment);
      if (!child.isPresent()) {
        break;
      }

      if (child.get().getValue() != null) {
        return true;
      }

      iter = child.get();
    }

    return false;
  }

  @Override
  public boolean putIfNoPrefixPresent(Trie.Key<K> key, V value) {
    if (hasPrefixValues(key)) {
      return false;
    }

    getOrCreateNode(key).setValue(value);
    return true;
  }

  @Override
  public boolean remove(Trie.Key<K> key) {
    return removeNode(key).isPresent();
  }

  private DefaultTrieNode<K, V> getOrCreateNode(Trie.Key<K> key) {
    DefaultTrieNode<K, V> iter = root;
    for (K segment : key.getSegments()) {
      iter = iter.getOrCreateChild(segment);
    }
    return iter;
  }

  private Optional<DefaultTrieNode<K, V>> removeNode(Trie.Key<K> key) {
    Optional<DefaultTrieNode<K, V>> maybeNode = getExactNode(key);
    if (!maybeNode.isPresent()) {
      return Optional.empty();
    }

    DefaultTrieNode<K, V> node = maybeNode.get();
    if (!node.isLeaf()) {
      V oldValue = node.getValue();
      node.setValue(null);
      return Optional.ofNullable(oldValue).map(ignore -> node);
    }

    // physically remove node and parents if needed
    K previousKey = node.getKey();
    DefaultTrieNode<K, V> iter = node.getParent();
    while (iter != null) {
      iter.removeChild(previousKey);
      if (!iter.isLeaf() || iter.getValue() != null) {
        break;
      }

      iter = iter.getParent();
    }

    return Optional.of(node);
  }

  private Optional<DefaultTrieNode<K, V>> getExactNode(Trie.Key<K> key) {
    DefaultTrieNode<K, V> iter = root;
    for (K segment : key.getSegments()) {
      Optional<DefaultTrieNode<K, V>> child = iter.getChild(segment);
      if (!child.isPresent()) {
        return Optional.empty();
      }

      iter = child.get();
    }

    return Optional.ofNullable(iter);
  }
}
