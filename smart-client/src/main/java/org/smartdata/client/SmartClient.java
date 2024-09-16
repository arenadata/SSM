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
package org.smartdata.client;

import org.apache.commons.collections.CollectionUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.ipc.ProtobufRpcEngine2;
import org.apache.hadoop.ipc.RPC;
import org.smartdata.client.activeserver.ActiveServerAddressCache;
import org.smartdata.client.fileaccess.FileAccessReportStrategy;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.metrics.FileAccessEvent;
import org.smartdata.model.FileState;
import org.smartdata.model.NormalFileState;
import org.smartdata.model.PathChecker;
import org.smartdata.protocol.SmartClientProtocol;
import org.smartdata.protocol.protobuffer.ClientProtocolClientSideTranslator;
import org.smartdata.protocol.protobuffer.ClientProtocolProtoBuffer;

import java.io.Closeable;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import static org.smartdata.utils.ConfigUtil.getSsmRpcAddresses;

public class SmartClient implements Closeable, SmartClientProtocol {
  private static final long VERSION = 1;
  private static final int SINGLE_IGNORE_FILES_INITIAL_CAPACITY = 200;

  private final Configuration conf;
  private final SmartServerHandles smartServerHandles;
  private final Set<String> singleIgnoreFiles;
  private final PathChecker pathChecker;
  private final FileAccessReportStrategy fileAccessReportStrategy;
  private final ActiveServerAddressCache activeServerAddressCache;
  private volatile boolean running = true;

  public SmartClient(Configuration conf) throws IOException {
    this(conf, getSsmRpcAddresses(conf));
  }

  public SmartClient(Configuration conf, InetSocketAddress ssmRpcAddress) throws IOException {
    this(conf, Collections.singletonList(ssmRpcAddress));
  }

  public SmartClient(Configuration conf, List<InetSocketAddress> ssmRpcAddresses)
      throws IOException {
    this(conf, ssmRpcAddresses, ActiveServerAddressCache.fileCache(conf));
  }

  public SmartClient(
      Configuration conf,
      List<InetSocketAddress> ssmRpcAddresses,
      ActiveServerAddressCache activeServerAddressCache)
      throws IOException {
    this.conf = conf;
    this.singleIgnoreFiles = ConcurrentHashMap.newKeySet(SINGLE_IGNORE_FILES_INITIAL_CAPACITY);
    this.pathChecker = new PathChecker(conf);
    this.activeServerAddressCache = activeServerAddressCache;
    this.smartServerHandles = new SmartServerHandles(
        initializeServerHandles(ssmRpcAddresses));
    this.fileAccessReportStrategy = FileAccessReportStrategy.from(conf, smartServerHandles);
  }

  private List<SmartServerHandle> initializeServerHandles(
      List<InetSocketAddress> addresses) throws IOException {
    if (CollectionUtils.isEmpty(addresses)) {
      throw new IllegalArgumentException("Empty list of SSM RPC addresses");
    }

    RPC.setProtocolEngine(
        conf, ClientProtocolProtoBuffer.class, ProtobufRpcEngine2.class);

    Iterable<InetSocketAddress> orderedAddresses = activeServerAddressCache.get()
        .map(activeServerAddress ->
            getOrderedServerAddresses(activeServerAddress, addresses))
        .orElse(addresses);

    List<SmartServerHandle> serverHandles = new ArrayList<>();

    for (InetSocketAddress addr : orderedAddresses) {
      ClientProtocolProtoBuffer proxy = RPC.getProxy(
          ClientProtocolProtoBuffer.class, VERSION, addr, conf);
      SmartClientProtocol server = new ClientProtocolClientSideTranslator(proxy);
      serverHandles.add(new SmartServerHandle(server, addr));
    }
    return serverHandles;
  }

  /**
   * Reports access count event to smart server. In SSM HA mode, multiple
   * smart servers can be configured. If fail to connect to one server,
   * this method will pick up the next one from a queue to try again. If
   * all servers cannot be connected, an exception will be thrown.
   * <p></p>
   * Generally, Configuration class has only one instance. If this method
   * finds active server has been changed, it will reset the value for
   * property SMART_SERVER_RPC_ADDRESS_KEY in Configuration instance. Thus,
   * next time a SmartClient is created with this Configuration instance,
   * active server will be put in the head of a queue and it will be picked
   * up firstly.
   */
  @Override
  public void reportFileAccessEvent(FileAccessEvent event)
      throws IOException {
    if (shouldIgnore(event.getPath())) {
      return;
    }
    checkOpen();

    SmartServerHandle reportedServerHandle =
        fileAccessReportStrategy.reportFileAccessEvent(event);

    maybeUpdateActiveSmartServer(reportedServerHandle);
  }

  @Override
  public FileState getFileState(String filePath) throws IOException {
    checkOpen();

    for (SmartServerHandle serverHandle : smartServerHandles.handles()) {
      try {
        FileState fileState = serverHandle.getProtocol().getFileState(filePath);
        maybeUpdateActiveSmartServer(serverHandle);
        return fileState;
      } catch (ConnectException exception) {
        // try next server
      }
    }

    // client cannot connect to servers
    // don't report access event for this file this time
    singleIgnoreFiles.add(filePath);

    // Assume the given file is normal, but serious error can occur if
    // the file is compacted or compressed by SSM.
    return new NormalFileState(filePath);
  }

  public boolean shouldIgnore(String path) {
    if (singleIgnoreFiles.remove(path)) {
      // this report should be ignored
      return true;
    }
    return pathChecker.isIgnored(path)
        || !pathChecker.isCovered(path);
  }

  @Override
  public void close() throws IOException {
    if (running) {
      running = false;
      for (SmartServerHandle server : smartServerHandles.handles()) {
        RPC.stopProxy(server.getProtocol());
      }

      fileAccessReportStrategy.close();
    }
  }

  private Collection<InetSocketAddress> getOrderedServerAddresses(
      InetSocketAddress activeServerAddress,
      Collection<InetSocketAddress> serverAddresses) {

    Set<InetSocketAddress> orderedServers = new LinkedHashSet<>();
    // last active server address should be first
    orderedServers.add(activeServerAddress);
    orderedServers.addAll(serverAddresses);
    return orderedServers;
  }

  private void checkOpen() throws IOException {
    if (!running) {
      throw new IOException("SmartClient closed");
    }
  }

  private void maybeUpdateActiveSmartServer(SmartServerHandle newActiveServer) {
    if (!newActiveServer.equals(smartServerHandles.activeServer())) {
      onNewActiveSmartServer(newActiveServer);
    }
  }

  /**
   * Reset smart server address in conf and a local file to reflect the
   * changes of active smart server in fail over.
   */
  private void onNewActiveSmartServer(SmartServerHandle newActiveServer) {
    smartServerHandles.withNewActiveServer(newActiveServer);

    String joinedSsmAddresses = smartServerHandles.handles()
        .stream()
        .map(SmartServerHandle::getAddress)
        .map(InetSocketAddress::toString)
        .collect(Collectors.joining(","));

    conf.set(SmartConfKeys.SMART_SERVER_RPC_ADDRESS_KEY, joinedSsmAddresses);

    activeServerAddressCache.put(newActiveServer.getAddress());
  }
}
