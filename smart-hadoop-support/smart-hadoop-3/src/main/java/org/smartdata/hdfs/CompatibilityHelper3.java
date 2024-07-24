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
import org.apache.hadoop.fs.*;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.hdfs.DFSClient;
import org.apache.hadoop.hdfs.DFSInputStream;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.hdfs.SmartInputStream;
import org.apache.hadoop.hdfs.SmartStripedInputStream;
import org.apache.hadoop.hdfs.inotify.Event;
import org.apache.hadoop.hdfs.protocol.*;
import org.apache.hadoop.hdfs.protocol.datatransfer.Sender;
import org.apache.hadoop.hdfs.protocol.proto.InotifyProtos;
import org.apache.hadoop.hdfs.protocolPB.PBHelperClient;
import org.apache.hadoop.hdfs.security.token.block.BlockTokenIdentifier;
import org.apache.hadoop.hdfs.server.balancer.KeyManager;
import org.apache.hadoop.hdfs.server.blockmanagement.DatanodeDescriptor;
import org.apache.hadoop.hdfs.server.namenode.ErasureCodingPolicyManager;
import org.apache.hadoop.hdfs.server.protocol.DatanodeStorage;
import org.apache.hadoop.hdfs.server.protocol.StorageReport;
import org.apache.hadoop.security.token.Token;
import org.smartdata.SmartConstants;
import org.smartdata.hdfs.action.move.DBlock;
import org.smartdata.hdfs.action.move.StorageGroup;
import org.smartdata.hdfs.action.move.DBlockStriped;
import org.smartdata.model.FileState;

import java.io.*;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class CompatibilityHelper3 implements CompatibilityHelper {
  @Override
  public List<String> getStorageTypes(LocatedBlock lb) {
    return Arrays.stream(lb.getStorageTypes())
        .map(StorageType::toString)
        .collect(Collectors.toList());
  }

  @Override
  public void replaceBlock(
      DataOutputStream out,
      ExtendedBlock eb,
      String storageType,
      Token<BlockTokenIdentifier> accessToken,
      String dnUUID,
      DatanodeInfo info)
      throws IOException {
    new Sender(out).replaceBlock(eb, StorageType.valueOf(storageType), accessToken, dnUUID, info, null);
  }

  @Override
  public List<String> getMovableTypes() {
    return StorageType.getMovableTypes()
        .stream()
        .map(StorageType::toString)
        .collect(Collectors.toList());
  }

  @Override
  public String getStorageType(StorageReport report) {
    return report.getStorage().getStorageType().toString();
  }

  @Override
  public List<String> chooseStorageTypes(BlockStoragePolicy policy, short replication) {
    return policy.chooseStorageTypes(replication)
        .stream()
        .map(StorageType::toString)
        .collect(Collectors.toList());
  }

  @Override
  public DatanodeInfo newDatanodeInfo(String ipAddress, int xferPort) {
    DatanodeID datanodeID = new DatanodeID(ipAddress, null, null,
        xferPort, 0, 0, 0);
    return new DatanodeDescriptor(datanodeID);
  }

  @Override
  public int getSidInDatanodeStorageReport(DatanodeStorage datanodeStorage) {
    StorageType storageType = datanodeStorage.getStorageType();
    return storageType.ordinal();
  }

  @Override
  public OutputStream getDFSClientAppend(DFSClient client, String dest, int bufferSize, long offset, short replication)
      throws IOException {
    if (client.exists(dest) && offset != 0) {
      return getDFSClientAppend(client, dest, bufferSize);
    }
    return client.create(dest, true, replication, client.getConf().getDefaultBlockSize());
  }

  @Override
  public OutputStream getDFSClientAppend(DFSClient client, String dest,
                                         int bufferSize, long offset) throws IOException {
    return getDFSClientAppend(client, dest, bufferSize, offset, client.getConf().getDefaultReplication());
  }

  @Override
  public OutputStream getDFSClientAppend(DFSClient client, String dest,
                                         int bufferSize) throws IOException {
    return client.append(dest, bufferSize,
            EnumSet.of(CreateFlag.APPEND), null, null);
  }

  @Override
  public OutputStream getS3outputStream(String dest, Configuration conf) throws IOException {
    // Copy to remote S3
    if (!dest.startsWith("s3")) {
      throw new IOException();
    }
    // Copy to s3
    FileSystem fs = FileSystem.get(URI.create(dest), conf);
    return fs.create(new Path(dest), true);
  }

  @Override
  public Token<BlockTokenIdentifier> getAccessToken(
      KeyManager km, ExtendedBlock eb, StorageGroup target) throws IOException {
    return km.getAccessToken(eb, new StorageType[]{StorageType.parseStorageType(target.getStorageType())}, new String[0]);
  }

  @Override
  public InputStream getVintPrefixed(DataInputStream in) throws IOException {
    return PBHelperClient.vintPrefixed(in);
  }

  @Override
  public LocatedBlocks getLocatedBlocks(HdfsLocatedFileStatus status) {
    return status.getLocatedBlocks();
  }

  @Override
  public byte getErasureCodingPolicy(HdfsFileStatus fileStatus) {
    ErasureCodingPolicy erasureCodingPolicy = fileStatus.getErasureCodingPolicy();
    // null means replication policy and its id is 0 in HDFS.
    if (erasureCodingPolicy == null) {
      return (byte) 0;
    }
    return fileStatus.getErasureCodingPolicy().getId();
  }

  @Override
  public String getErasureCodingPolicyName(HdfsFileStatus fileStatus) {
    ErasureCodingPolicy erasureCodingPolicy = fileStatus.getErasureCodingPolicy();
    if (erasureCodingPolicy == null) {
      return SmartConstants.REPLICATION_CODEC_NAME;
    }
    return erasureCodingPolicy.getName();
  }

  @Override
  public byte getErasureCodingPolicyByName(DFSClient client, String ecPolicyName) throws IOException {
    if (ecPolicyName.equals(SystemErasureCodingPolicies.getReplicationPolicy().getName())) {
      return (byte) 0;
    }
    for (ErasureCodingPolicyInfo policyInfo : client.getErasureCodingPolicies()) {
      if (policyInfo.getPolicy().getName().equals(ecPolicyName)) {
        return policyInfo.getPolicy().getId();
      }
    }
    return (byte) -1;
  }

  @Override
  public Map<Byte, String> getErasureCodingPolicies(DFSClient dfsClient) throws IOException {
    Map<Byte, String> policies = new HashMap<>();
    /**
     * The replication policy is excluded by the get method of client,
     * but it should also be put. Its id is always 0.
     */
    policies.put((byte) 0, SystemErasureCodingPolicies.getReplicationPolicy().getName());
    for (ErasureCodingPolicyInfo policyInfo : dfsClient.getErasureCodingPolicies()) {
      ErasureCodingPolicy policy = policyInfo.getPolicy();
      policies.put(policy.getId(), policy.getName());
    }
    return policies;
  }


  @Override
  public List<String> getStorageTypeForEcBlock(
      LocatedBlock lb, BlockStoragePolicy policy, byte policyId) throws IOException {
    if (lb.isStriped()) {
      //TODO: verify the current storage policy (policyID) or the target one
      //TODO: output log for unsupported storage policy for EC block
      String policyName = policy.getName();
      // Exclude onessd/onedisk action to be executed on EC block.
      // EC blocks can only be put on a same storage medium.
      if (policyName.equalsIgnoreCase("Warm") |
          policyName.equalsIgnoreCase("One_SSD") |
          policyName.equalsIgnoreCase("Lazy_Persist")) {
        throw new IOException("onessd/onedisk/ramdisk is not applicable to EC block!");
      }
      if (ErasureCodingPolicyManager
          .checkStoragePolicySuitableForECStripedMode(policyId)) {
        return chooseStorageTypes(policy, (short) lb.getLocations().length);
      } else {
        throw new IOException("Unsupported storage policy for EC block: " + policy.getName());
      }
    }
    return null;
  }

  @Override
  public DBlock newDBlock(LocatedBlock lb, HdfsFileStatus status) {
    Block blk = lb.getBlock().getLocalBlock();
    ErasureCodingPolicy ecPolicy = status.getErasureCodingPolicy();
    DBlock db;
    if (lb.isStriped()) {
      LocatedStripedBlock lsb = (LocatedStripedBlock) lb;
      byte[] indices = new byte[lsb.getBlockIndices().length];
      for (int i = 0; i < indices.length; i++) {
        indices[i] = lsb.getBlockIndices()[i];
      }
      db = new DBlockStriped(blk, indices, (short) ecPolicy.getNumDataUnits(),
          ecPolicy.getCellSize());
    } else {
      db = new DBlock(blk);
    }
    return db;
  }

  @Override
  public DBlock getDBlock(DBlock block, StorageGroup source) {
    if (block instanceof DBlockStriped) {
      return ((DBlockStriped) block).getInternalBlock(source);
    }
    return block;
  }

  @Override
  public DFSInputStream getNormalInputStream(DFSClient dfsClient, String src, boolean verifyChecksum,
      FileState fileState) throws IOException {
    LocatedBlocks locatedBlocks = dfsClient.getLocatedBlocks(src, 0);
    ErasureCodingPolicy ecPolicy = locatedBlocks.getErasureCodingPolicy();
    if (ecPolicy != null) {
      return new SmartStripedInputStream(dfsClient, src, verifyChecksum, ecPolicy, locatedBlocks, fileState);
    }
    return new SmartInputStream(dfsClient, src, verifyChecksum, fileState);
  }
}