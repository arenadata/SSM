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
package org.smartdata.ozone;

import lombok.extern.slf4j.Slf4j;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.ozone.RootedOzoneFileSystem;
import org.apache.hadoop.ozone.client.OzoneClientFactory;
import org.smartdata.AbstractService;
import org.smartdata.SmartContext;
import org.smartdata.ozone.handler.AsyncFsObjectStreamHandler;
import org.smartdata.ozone.handler.DbFsObjectHandler;
import org.smartdata.ozone.handler.FsObjectHandler;
import org.smartdata.ozone.handler.FsObjectStreamHandler;
import org.smartdata.ozone.model.FsObjectStreamRecord;
import org.smartdata.ozone.snapshot.OfsSnapshotFetcher;

import java.io.IOException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
public class OzoneFetcherService extends AbstractService {
  private final OzoneSmartConf ozoneSmartConf;
  private final OzoneFileInfoDao ozoneFileInfoDao;

  private OfsSnapshotFetcher ofsSnapshotFetcher;
  private FsObjectStreamHandler eventStreamHandler;

  public OzoneFetcherService(
      SmartContext context,
      OzoneFileInfoDao ozoneFileInfoDao) {
    super(context);
    this.ozoneSmartConf = new OzoneSmartConf(context.getConf());
    this.ozoneFileInfoDao = ozoneFileInfoDao;
  }

  @Override
  public void init() throws IOException {
    try {
      ofsSnapshotFetcher = buildSnapshotFetcher();
      eventStreamHandler = buildStreamHandler();
    } catch (Exception exception) {
      throw new IOException("Error initializing Ozone fetcher services", exception);
    }
  }

  private OfsSnapshotFetcher buildSnapshotFetcher() throws IOException {
    ExecutorService executorService = Executors.newFixedThreadPool(
        ozoneSmartConf.getSnapshotFetcherThreadsCount());

    return new OfsSnapshotFetcher(
        buildOzoneFileSystem(),
        OzoneClientFactory.getRpcClient(ozoneSmartConf).getObjectStore(),
        ozoneSmartConf,
        executorService,
        ozoneSmartConf.getFetchBatchSize()
    );
  }

  private FileSystem buildOzoneFileSystem() throws IOException {
    // create RootedOzoneFileSystem directly because we don't need
    // a ssm client here
    RootedOzoneFileSystem fileSystem = new RootedOzoneFileSystem();
    fileSystem.initialize(ozoneSmartConf.getOzoneDefaultFsUri(), ozoneSmartConf);
    return fileSystem;
  }

  private FsObjectStreamHandler buildStreamHandler() {
    return new AsyncFsObjectStreamHandler(
        buildFsObjectHandler(),
        Executors.newSingleThreadExecutor()
    );
  }

  private FsObjectHandler buildFsObjectHandler() {
    return new DbFsObjectHandler(ozoneFileInfoDao);
  }

  @Override
  public void start() {
    BlockingQueue<FsObjectStreamRecord> fsObjectStream = ofsSnapshotFetcher.runSnapshot();
    eventStreamHandler.collectAsync(fsObjectStream);
  }

  @Override
  public void stop() throws IOException {
    try {
      ofsSnapshotFetcher.close();
    } catch (Exception exception) {
      log.error("Error closing snapshot fetcher", exception);
    }

    try {
      eventStreamHandler.close();
    } catch (Exception e) {
      log.error("Error closing event stream handler", e);
    }
  }
}
