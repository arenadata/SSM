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

import lombok.Data;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Data
public class DefaultTrieNode<K, V> implements Trie.Node<K, V> {
    private final K key;
    private final DefaultTrieNode<K, V> parent;
    private final Map<K, DefaultTrieNode<K, V>> children;

    private volatile V value;

    public DefaultTrieNode(K key, DefaultTrieNode<K, V> parent, V value) {
        this.key = key;
        this.value = value;
        this.parent = parent;
        this.children = new ConcurrentHashMap<>();
    }

    public DefaultTrieNode(K key, DefaultTrieNode<K, V> parent) {
        this(key, parent, null);
    }

    public void removeChild(K key) {
        children.remove(key);
    }

    public Optional<DefaultTrieNode<K, V>> getChild(K key) {
        DefaultTrieNode<K, V> child = children.get(key);
        return Optional.ofNullable(child);
    }

    public boolean isLeaf() {
        return children.isEmpty();
    }

    public DefaultTrieNode<K, V> getOrCreateChild(K key) {
        return children.computeIfAbsent(key, childKey -> new DefaultTrieNode<>(childKey, this));
    }

    @Override
    public String toString() {
        return "DefaultTrieNode{" +
            "key=" + key +
            ", value=" + value +
            '}';
    }
}
