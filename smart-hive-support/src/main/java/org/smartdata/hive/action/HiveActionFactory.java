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
package org.smartdata.hive.action;

import org.smartdata.action.AbstractActionFactory;
import org.smartdata.action.SmartAction;
import org.smartdata.action.SyncAction;
import org.smartdata.hive.action.constraint.HmsCreateConstraintAction;
import org.smartdata.hive.action.constraint.HmsDropConstraintAction;
import org.smartdata.hive.action.db.HmsAlterDbAction;
import org.smartdata.hive.action.db.HmsCreateDbAction;
import org.smartdata.hive.action.db.HmsDropDbAction;
import org.smartdata.hive.action.function.HmsCreateFunctionAction;
import org.smartdata.hive.action.function.HmsDropFunctionAction;
import org.smartdata.hive.action.partition.HmsAlterPartitionAction;
import org.smartdata.hive.action.partition.HmsCreatePartitionAction;
import org.smartdata.hive.action.partition.HmsDropPartitionAction;
import org.smartdata.hive.action.stats.HmsAlterPartitionColumnStatsAction;
import org.smartdata.hive.action.stats.HmsAlterTableColumnStatsAction;
import org.smartdata.hive.action.stats.HmsDropPartitionColumnStatsAction;
import org.smartdata.hive.action.stats.HmsDropTableColumnStatsAction;
import org.smartdata.hive.action.table.HmsAlterTableAction;
import org.smartdata.hive.action.table.HmsCreateTableAction;
import org.smartdata.hive.action.table.HmsDropTableAction;

import java.util.Arrays;
import java.util.List;

public class HiveActionFactory extends AbstractActionFactory {
  @Override
  protected List<Class<? extends SmartAction>> supportedActionClasses() {
    return Arrays.asList(
        HmsSyncAction.class,

        HmsCreateDbAction.class,
        HmsAlterDbAction.class,
        HmsDropDbAction.class,

        HmsCreateTableAction.class,
        HmsAlterTableAction.class,
        HmsDropTableAction.class,

        HmsCreateFunctionAction.class,
        HmsDropFunctionAction.class,

        HmsCreatePartitionAction.class,
        HmsAlterPartitionAction.class,
        HmsDropPartitionAction.class,

        HmsCreateConstraintAction.class,
        HmsDropConstraintAction.class,

        HmsAlterPartitionColumnStatsAction.class,
        HmsAlterTableColumnStatsAction.class,
        HmsDropPartitionColumnStatsAction.class,
        HmsDropTableColumnStatsAction.class,

        SyncAction.class
    );
  }
}
