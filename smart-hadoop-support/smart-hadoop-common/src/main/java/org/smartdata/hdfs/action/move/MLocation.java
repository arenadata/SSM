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
package org.smartdata.hdfs.action.move;

import org.apache.hadoop.hdfs.protocol.DatanodeInfo;
import org.apache.hadoop.hdfs.protocol.LocatedBlock;
import org.smartdata.hdfs.CompatibilityHelperLoader;

import java.util.LinkedList;
import java.util.List;

/**
 * A class to manage the datanode, storage type and size information of a block
 * replication.
 */
public class MLocation {
  final DatanodeInfo datanode;
  final String storageType;
  final long size;

  public MLocation(DatanodeInfo datanode, String storageType, long size) {
    this.datanode = datanode;
    this.storageType = storageType;
    this.size = size;
  }

  /**
   * Return a list of MLocation referring to all replications of a block.
   * @param lb
   * @return
   */
  public static List<MLocation> toLocations(LocatedBlock lb) {
    final DatanodeInfo[] datanodeInfos = lb.getLocations();
    final List<String> storageTypes = CompatibilityHelperLoader.getHelper().getStorageTypes(lb);
    final long size = lb.getBlockSize();
    final List<MLocation> locations = new LinkedList<MLocation>();
    for (int i = 0; i < datanodeInfos.length; i++) {
      locations.add(new MLocation(datanodeInfos[i], storageTypes.get(i), size));
    }
    return locations;
  }

  public String getStorageType() {
    return storageType;
  }
}
