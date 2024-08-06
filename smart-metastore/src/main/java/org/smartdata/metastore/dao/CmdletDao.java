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
package org.smartdata.metastore.dao;

import org.smartdata.metastore.queries.sort.CmdletSortField;
import org.smartdata.model.CmdletInfo;
import org.smartdata.model.CmdletState;
import org.smartdata.model.request.CmdletSearchRequest;

import java.util.List;

public interface CmdletDao extends Searchable<CmdletSearchRequest, CmdletInfo, CmdletSortField> {
  CmdletInfo getById(long id);

  List<CmdletInfo> getByRuleId(long ruleId);

  List<CmdletInfo> getByState(CmdletState state);

  long getNumCmdletsInTerminiatedStates();

  boolean delete(long id);

  void batchDelete(List<Long> ids);

  int deleteBeforeTime(long timestamp);

  int deleteKeepNewCmd(long num);

  void insert(CmdletInfo cmdletInfo);

  void insert(CmdletInfo... cmdletInfos);

  void upsert(List<CmdletInfo> cmdletInfos);

  int update(CmdletInfo cmdletInfo);

  int[] update(List<CmdletInfo> cmdletInfos);

  long getMaxId();
}
