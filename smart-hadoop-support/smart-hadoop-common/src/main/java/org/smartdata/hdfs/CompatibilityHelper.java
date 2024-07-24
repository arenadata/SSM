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
package org.smartdata.hdfs;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hdfs.DFSClient;
import org.apache.hadoop.hdfs.DFSInputStream;
import org.apache.hadoop.hdfs.inotify.Event;
import org.apache.hadoop.hdfs.protocol.BlockStoragePolicy;
import org.apache.hadoop.hdfs.protocol.DatanodeInfo;
import org.apache.hadoop.hdfs.protocol.ExtendedBlock;
import org.apache.hadoop.hdfs.protocol.HdfsFileStatus;
import org.apache.hadoop.hdfs.protocol.HdfsLocatedFileStatus;
import org.apache.hadoop.hdfs.protocol.LocatedBlock;
import org.apache.hadoop.hdfs.protocol.LocatedBlocks;
import org.apache.hadoop.hdfs.protocol.proto.InotifyProtos;
import org.apache.hadoop.hdfs.security.token.block.BlockTokenIdentifier;
import org.apache.hadoop.hdfs.server.balancer.KeyManager;
import org.apache.hadoop.hdfs.server.protocol.DatanodeStorage;
import org.apache.hadoop.hdfs.server.protocol.StorageReport;
import org.apache.hadoop.security.token.Token;
import org.smartdata.hdfs.action.move.DBlock;
import org.smartdata.hdfs.action.move.StorageGroup;
import org.smartdata.model.FileState;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.Map;

public interface CompatibilityHelper {
  List<String> getStorageTypes(LocatedBlock lb);

  void replaceBlock(
      DataOutputStream out,
      ExtendedBlock eb,
      String storageType,
      Token<BlockTokenIdentifier> accessToken,
      String dnUUID,
      DatanodeInfo info)
      throws IOException;

  List<String> getMovableTypes();

  String getStorageType(StorageReport report);

  List<String> chooseStorageTypes(BlockStoragePolicy policy, short replication);

  DatanodeInfo newDatanodeInfo(String ipAddress, int xferPort);

  int getSidInDatanodeStorageReport(DatanodeStorage datanodeStorage);

  OutputStream getDFSClientAppend(DFSClient client, String dest,
                                  int bufferSize, long offset, short replication)
      throws IOException;

  OutputStream getDFSClientAppend(DFSClient client, String dest, int bufferSize, long offset)
      throws IOException;

  OutputStream getDFSClientAppend(DFSClient client, String dest, int bufferSize) throws IOException;

  OutputStream getS3outputStream(String dest, Configuration conf) throws IOException;

  Token<BlockTokenIdentifier> getAccessToken(KeyManager km, ExtendedBlock eb, StorageGroup target)
      throws IOException;

  InputStream getVintPrefixed(DataInputStream in) throws IOException;

  LocatedBlocks getLocatedBlocks(HdfsLocatedFileStatus status);

  byte getErasureCodingPolicy(HdfsFileStatus fileStatus);

  String getErasureCodingPolicyName(HdfsFileStatus fileStatus);

  byte getErasureCodingPolicyByName(DFSClient client, String ecPolicyName) throws IOException;

  Map<Byte, String> getErasureCodingPolicies(DFSClient client) throws IOException;

  List<String> getStorageTypeForEcBlock(LocatedBlock lb, BlockStoragePolicy policy, byte policyId)
      throws IOException;

  DBlock newDBlock(LocatedBlock lb, HdfsFileStatus status);

  DBlock getDBlock(DBlock block, StorageGroup source);

  DFSInputStream getNormalInputStream(DFSClient dfsClient, String src, boolean verifyChecksum,
                                      FileState fileState) throws IOException;
}
