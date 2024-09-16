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
package org.smartdata.protocol.protobuffer;

import org.apache.hadoop.thirdparty.protobuf.RpcController;
import org.apache.hadoop.thirdparty.protobuf.ServiceException;
import org.smartdata.model.FileState;
import org.smartdata.protocol.ClientServerProto;
import org.smartdata.protocol.ClientServerProto.GetFileStateRequestProto;
import org.smartdata.protocol.ClientServerProto.GetFileStateResponseProto;
import org.smartdata.protocol.ClientServerProto.ReportFileAccessEventRequestProto;
import org.smartdata.protocol.ClientServerProto.ReportFileAccessEventResponseProto;
import org.smartdata.protocol.SmartServerProtocols;

import java.io.IOException;

public class ServerProtocolsServerSideTranslator implements
    ServerProtocolsProtoBuffer,
    ClientServerProto.protoService.BlockingInterface {
  private final SmartServerProtocols server;

  public ServerProtocolsServerSideTranslator(SmartServerProtocols server) {
    this.server = server;
  }

  @Override
  public ReportFileAccessEventResponseProto reportFileAccessEvent(
      RpcController controller, ReportFileAccessEventRequestProto req)
      throws ServiceException {
    try {
      server.reportFileAccessEvent(ProtoBufferHelper.convert(req));
      return ReportFileAccessEventResponseProto.newBuilder().build();
    } catch (IOException e) {
      throw new ServiceException(e);
    }
  }

  @Override
  public GetFileStateResponseProto getFileState(RpcController controller,
                                                GetFileStateRequestProto req)
      throws ServiceException {
    try {
      String path = req.getFilePath();
      FileState fileState = server.getFileState(path);
      return GetFileStateResponseProto.newBuilder()
          .setFileState(ProtoBufferHelper.convert(fileState))
          .build();
    } catch (IOException e) {
      throw new ServiceException(e);
    }
  }
}
