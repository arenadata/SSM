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
package org.smartdata.server;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.hdfs.DFSUtil;
import org.apache.hadoop.ipc.ProtobufRpcEngine2;
import org.apache.hadoop.ipc.RPC;
import org.apache.hadoop.ipc.RetriableException;
import org.apache.hadoop.thirdparty.protobuf.BlockingService;
import org.smartdata.SmartPolicyProvider;
import org.smartdata.conf.SmartConfKeys;
import org.smartdata.metastore.MetaStoreException;
import org.smartdata.metrics.FileAccessEvent;
import org.smartdata.model.FileState;
import org.smartdata.protocol.ClientServerProto;
import org.smartdata.protocol.SmartServerProtocols;
import org.smartdata.protocol.protobuffer.ClientProtocolProtoBuffer;
import org.smartdata.protocol.protobuffer.ServerProtocolsServerSideTranslator;

import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * Implements the rpc calls.
 * TODO: Implement statistics for SSM rpc server
 */
public class SmartRpcServer implements SmartServerProtocols {
  protected SmartServer ssm;
  protected Configuration conf;
  protected final InetSocketAddress clientRpcAddress;
  protected int serviceHandlerCount;
  protected final RPC.Server clientRpcServer;

  public SmartRpcServer(SmartServer ssm, Configuration conf) throws IOException {
    this.ssm = ssm;
    this.conf = conf;
    InetSocketAddress rpcAddr = getRpcServerAddress();
    RPC.setProtocolEngine(conf, ClientProtocolProtoBuffer.class,
        ProtobufRpcEngine2.class);

    ServerProtocolsServerSideTranslator clientSSMProtocolServerSideTranslatorPB =
        new ServerProtocolsServerSideTranslator(this);

    BlockingService clientSmartPbService = ClientServerProto.protoService
        .newReflectiveBlockingService(clientSSMProtocolServerSideTranslatorPB);

    serviceHandlerCount = conf.getInt(
        SmartConfKeys.SMART_SERVER_RPC_HANDLER_COUNT_KEY,
        SmartConfKeys.SMART_SERVER_RPC_HANDLER_COUNT_DEFAULT);

    clientRpcServer = new RPC.Builder(conf)
        .setProtocol(ClientProtocolProtoBuffer.class)
        .setInstance(clientSmartPbService)
        .setBindAddress(rpcAddr.getHostName())
        .setPort(rpcAddr.getPort())
        .setNumHandlers(serviceHandlerCount)
        .setVerbose(true)
        .build();

    InetSocketAddress listenAddr = clientRpcServer.getListenerAddress();
    clientRpcAddress = new InetSocketAddress(
        rpcAddr.getHostName(), listenAddr.getPort());

    DFSUtil.addPBProtocol(conf, ClientProtocolProtoBuffer.class,
        clientSmartPbService, clientRpcServer);

    boolean serviceAuthEnabled = conf.getBoolean(
        CommonConfigurationKeys.HADOOP_SECURITY_AUTHORIZATION, false);
    // set service-level authorization security policy
    if (serviceAuthEnabled) {
      clientRpcServer.refreshServiceAcl(conf, new SmartPolicyProvider());
    }
  }

  private InetSocketAddress getRpcServerAddress() {
    String[] strings = conf.get(SmartConfKeys.SMART_SERVER_RPC_ADDRESS_KEY,
        SmartConfKeys.SMART_SERVER_RPC_ADDRESS_DEFAULT).split(":");
    return new InetSocketAddress(strings[strings.length - 2]
        , Integer.parseInt(strings[strings.length - 1]));
  }

  /**
   * Start SSM RPC service.
   */
  public void start() {
    if (clientRpcServer != null) {
      clientRpcServer.start();
    }
  }

  /**
   * Stop SSM RPC service.
   */
  public void stop() {
    if (clientRpcServer != null) {
      clientRpcServer.stop();
    }
  }

  /*
   * Waiting for RPC threads to exit.
   */
  public void join() throws InterruptedException {
    if (clientRpcServer != null) {
      clientRpcServer.join();
    }
  }

  private void checkIfActive() throws IOException {
    if (!ssm.isActive()) {
      throw new RetriableException("SSM services not ready...");
    }
  }

  @Override
  public void reportFileAccessEvent(FileAccessEvent event)
      throws IOException {
    checkIfActive();
    ssm.getStatesManager().reportFileAccessEvent(event);
  }

  @Override
  public FileState getFileState(String filePath) throws IOException {
    checkIfActive();
    try {
      return ssm.getMetaStore().getFileState(filePath);
    } catch (MetaStoreException e) {
      throw new IOException(e);
    }
  }
}
