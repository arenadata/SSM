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
package org.smartdata.hdfs.metric.fetcher;

import com.google.common.collect.Sets;
import java.util.HashSet;
import java.util.Set;
import java.util.Optional;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.hdfs.DFSClient;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.hdfs.MiniDFSCluster;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.smartdata.model.FileInfo;
import org.smartdata.conf.SmartConf;
import org.smartdata.metastore.MetaStore;
import org.smartdata.metastore.MetaStoreException;

import static org.mockito.Mockito.*;
import static org.smartdata.conf.SmartConfKeys.SMART_IGNORED_PATH_TEMPLATES_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_IGNORE_DIRS_KEY;
import static org.smartdata.conf.SmartConfKeys.SMART_NAMESPACE_FETCH_INTERVAL_MS_KEY;

import java.io.IOException;
import java.util.ArrayList;

public class TestNamespaceFetcher {
  final Set<String> pathesInDB = new HashSet<>();

  NamespaceFetcher init(MiniDFSCluster cluster, SmartConf conf)
      throws IOException, MetaStoreException {
      final DistributedFileSystem dfs = cluster.getFileSystem();
      dfs.mkdir(new Path("/user"), new FsPermission("777"));
      dfs.create(new Path("/user/user1"));
      dfs.create(new Path("/user/user2"));
      // this file should be ignored in each case because of
      // the 'smart.internal.path.templates' option's default value
      dfs.create(new Path("/user/.tmpfile"));
      dfs.mkdir(new Path("/tmp"), new FsPermission("777"));
      DFSClient client = dfs.getClient();

      MetaStore adapter = Mockito.mock(MetaStore.class);
      doAnswer(new Answer<Void>() {
        @Override
        public Void answer(InvocationOnMock invocationOnMock) {
          try {
            Object[] objects = invocationOnMock.getArguments();
            for (FileInfo fileInfo : (FileInfo[]) objects[0]) {
              pathesInDB.add(fileInfo.getPath());
            }
          } catch (Throwable t) {
            t.printStackTrace();
          }
          return null;
        }
      }).when(adapter).insertFiles(any(FileInfo[].class));

      SmartConf nonNullConfig = Optional.ofNullable(conf)
          .orElseGet(SmartConf::new);
      nonNullConfig.setLong(SMART_NAMESPACE_FETCH_INTERVAL_MS_KEY, 100L);

      return new NamespaceFetcher(client, adapter, nonNullConfig);
  }

  @Test
  public void testFetchingFromRoot() throws IOException, InterruptedException,
      MetaStoreException {
    pathesInDB.clear();
    Configuration conf = new SmartConf();
    final MiniDFSCluster cluster = new MiniDFSCluster.Builder(conf)
        .numDataNodes(2).build();
    try {
      NamespaceFetcher fetcher = init(cluster, null);
      fetcher.startFetch();
      Set<String> expected = Sets.newHashSet("/", "/user", "/user/user1", "/user/user2", "/tmp");
      while (!fetcher.fetchFinished()) {
        Thread.sleep(100);
      }
      Assert.assertEquals(expected, pathesInDB);
      fetcher.stop();
    } finally {
      cluster.shutdown();
    }
  }

  @Test
  public void testFetchingFromGivenDir() throws IOException, InterruptedException,
      MetaStoreException {
    pathesInDB.clear();
    final Configuration conf = new SmartConf();
    final MiniDFSCluster cluster = new MiniDFSCluster.Builder(conf)
        .numDataNodes(2).build();
    String fetchDir = "/user";
    try {
      NamespaceFetcher fetcher = init(cluster, null);
      fetcher.startFetch(fetchDir);
      Set<String> expected = Sets.newHashSet("/user", "/user/user1", "/user/user2");
      while (!fetcher.fetchFinished()) {
        Thread.sleep(100);
      }
      Assert.assertEquals(expected, pathesInDB);
      fetcher.stop();
    } finally {
      cluster.shutdown();
    }
  }

  @Test
  public void testIgnore() throws IOException, InterruptedException,
      MetaStoreException {
    pathesInDB.clear();
    final SmartConf conf = new SmartConf();
    final MiniDFSCluster cluster = new MiniDFSCluster.Builder(conf)
        .numDataNodes(2).build();
    conf.set(SMART_IGNORE_DIRS_KEY, "/tmp");
    try {
      NamespaceFetcher fetcher = init(cluster, conf);
      fetcher.startFetch();
      Set<String> expected = Sets.newHashSet("/", "/user", "/user/user1", "/user/user2");
      while (!fetcher.fetchFinished()) {
        Thread.sleep(100);
      }
      Assert.assertEquals(expected, pathesInDB);
      fetcher.stop();
    } finally {
      cluster.shutdown();
    }
  }

  @Test
  public void testIgnorePathTemplate() throws IOException, InterruptedException,
      MetaStoreException {
    pathesInDB.clear();
    final SmartConf conf = new SmartConf();
    final MiniDFSCluster cluster = new MiniDFSCluster.Builder(conf)
        .numDataNodes(2).build();
    conf.set(SMART_IGNORED_PATH_TEMPLATES_KEY, ".*user2.*,/tmp.*");
    try {
      NamespaceFetcher fetcher = init(cluster, conf);
      fetcher.startFetch();
      Set<String> expected = Sets.newHashSet("/", "/user", "/user/user1");
      while (!fetcher.fetchFinished()) {
        Thread.sleep(100);
      }
      Assert.assertEquals(expected, pathesInDB);

      fetcher.stop();
    } finally {
      cluster.shutdown();
    }
  }

  @Test
  public void testFetch() throws IOException, InterruptedException,
      MetaStoreException {
    pathesInDB.clear();
    final SmartConf conf = new SmartConf();
    final MiniDFSCluster cluster = new MiniDFSCluster.Builder(conf)
        .numDataNodes(2).build();
    ArrayList<String> coverList = new ArrayList<>();
    coverList.add("/user");
    conf.setCoverDir(coverList);
    try {
      NamespaceFetcher fetcher = init(cluster, conf);
      fetcher.startFetch();
      Set<String> expected = Sets.newHashSet("/user/", "/user/user1", "/user/user2");
      while (!fetcher.fetchFinished()) {
        Thread.sleep(100);
      }
      Assert.assertEquals(expected, pathesInDB);
      fetcher.stop();
    } finally {
      cluster.shutdown();
    }
  }
}