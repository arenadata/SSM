/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.smartdata.model;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public class TestPathCheckerThreadSafety {

  private static final int NUM_WORKERS = 10;
  private static final int NUM_PATHS = 1000;

  // we need to use paths of different lengths to potentially raise
  // ArrayIndexOutOfBoundsException in case of wrong multithreading behavior in Matcher
  private static final List<String> TEST_PATHS = Arrays.asList(
      "short_path",
      "/some_dir/medium_size_path",
      "/test/dir/another/dir/extraordinary_long_size_path"
  );
  private static final String IGNORED_DIR = "/ignored/";

  private ExecutorService executor;
  private PathChecker pathChecker;
  private CyclicBarrier startBarrier;
  private AtomicInteger ignoredPathCounter;

  @Before
  public void init() throws Exception {
    executor = Executors.newFixedThreadPool(10);
    pathChecker = new PathChecker(
        Collections.singletonList("/ignored/*"),
        Collections.emptyList());
    startBarrier = new CyclicBarrier(NUM_WORKERS);
    ignoredPathCounter = new AtomicInteger();
  }

  @After
  public void shutdown() {
    executor.shutdownNow();
  }

  @Test
  public void checkThreadSafety() throws Exception {
    Random random = new Random();

    CompletableFuture<?>[] futures = IntStream.range(0, NUM_WORKERS)
        .mapToObj(ignore -> startWorker(random))
        .toArray(CompletableFuture[]::new);

    CompletableFuture.allOf(futures)
        .get(2, TimeUnit.SECONDS);
    Assert.assertEquals(ignoredPathCounter.get(), NUM_WORKERS);
  }

  private CompletableFuture<?> startWorker(Random random) {
    List<String> paths = Stream.generate(() -> nextPath(random))
        .limit(NUM_PATHS)
        .collect(Collectors.toList());

    int ignoredPathIndex = random.nextInt(NUM_PATHS);
    paths.set(ignoredPathIndex, IGNORED_DIR + paths.get(ignoredPathIndex));

    return CompletableFuture.runAsync(new Worker(paths), executor);
  }

  private String nextPath(Random random) {
    int nextIndex = random.nextInt(TEST_PATHS.size());
    return TEST_PATHS.get(nextIndex);
  }

  private class Worker implements Runnable {
    private final List<String> pathsToCheck;

    private Worker(List<String> pathsToCheck) {
      this.pathsToCheck = pathsToCheck;
    }

    @Override
    public void run() {
      try {
        startBarrier.await(1, TimeUnit.SECONDS);
      } catch (Exception e) {
        throw new RuntimeException("Error waiting start barrier", e);
      }

      for (String path: pathsToCheck) {
        if (pathChecker.isIgnored(path)) {
          ignoredPathCounter.incrementAndGet();
        }
      }
    }
  }
}
