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

package org.smartdata.hive.handler;

/**
 * Removes the state, collected from HMS during the previous fetches.
 *
 * <p>It is executed under the transaction of the new HMS snapshot,
 * so that the previous state stays visible until the new snapshot
 * is committed and is restored if the snapshot fails.
 */
public interface HmsSnapshotStateCleaner {
  HmsSnapshotStateCleaner NO_OP_CLEANER = () -> {};

  void clean() throws Exception;

  static HmsSnapshotStateCleaner noOp() {
    return NO_OP_CLEANER;
  }
}
