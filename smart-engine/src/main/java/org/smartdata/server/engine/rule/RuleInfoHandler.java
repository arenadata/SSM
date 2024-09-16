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
package org.smartdata.server.engine.rule;

import org.smartdata.metastore.dao.RuleDao;
import org.smartdata.metastore.dao.SearchableService;
import org.smartdata.metastore.queries.sort.RuleSortField;
import org.smartdata.model.RuleInfo;
import org.smartdata.model.request.RuleSearchRequest;

public class RuleInfoHandler extends
    SearchableService<RuleSearchRequest, RuleInfo, RuleSortField> {
  public RuleInfoHandler(RuleDao ruleDao) {
    super(ruleDao, "rules");
  }
}
