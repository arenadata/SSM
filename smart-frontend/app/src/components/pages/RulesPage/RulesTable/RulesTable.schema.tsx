/*
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
import type { TableColumnSchema } from '@uikit/Table/Table.types';
import { SchemaColumnType } from '@uikit/Table/Table.types';
import { TableDateRangePickerFilter, TableMultiSelectFilter, TableSearchFilter } from '@uikit/Table/TableFilter';
import type { AdhRule, AdhRuleFilter } from '@models/adh';
import { AdhRuleState } from '@models/adh';
import RuleStatusCell from './RuleStatusCell/RuleStatusCell';
import RuleActionsCell from './RuleActionsCell/RuleActionsCell';
import { getOptionsFromEnum } from '@uikit/Select/Select.utils';
import SmartRuleHighlighter from '@uikit/SmartRuleHighlighter/SmartRuleHighlighter';
import TableCell from '@uikit/Table/TableCell/TableCell';

const ruleStatesOptions = getOptionsFromEnum(AdhRuleState);

export const rulesColumns: TableColumnSchema[] = [
  {
    name: 'id',
    label: 'ID',
    isSortable: true,
  },
  {
    name: 'textRepresentation',
    label: 'Rule Text',
    filterRenderer: () => {
      return <TableSearchFilter<AdhRuleFilter> filterName="textRepresentationLike" placeholder="Search text like" />;
    },
    filterName: 'textRepresentationLike',
    schema: {
      cellRenderer: (rule: AdhRule) => {
        return (
          <TableCell>
            <SmartRuleHighlighter rule={rule.textRepresentation} />
          </TableCell>
        );
      },
    },
  },
  {
    name: 'submitTime',
    label: 'Submission Time',
    isSortable: true,
    filterRenderer: (closeFilter) => {
      return <TableDateRangePickerFilter<AdhRuleFilter> filterName="submissionTime" closeFilter={closeFilter} />;
    },
    filterName: 'submissionTime',
    schema: {
      type: SchemaColumnType.DateTime,
    },
  },
  {
    name: 'lastActivationTime',
    label: 'Last Check Time',
    isSortable: true,
    filterRenderer: (closeFilter) => {
      return <TableDateRangePickerFilter<AdhRuleFilter> filterName="lastActivationTime" closeFilter={closeFilter} />;
    },
    filterName: 'lastActivationTime',
    schema: {
      type: SchemaColumnType.DateTime,
    },
  },
  {
    name: 'activationCount',
    label: 'Checked number',
    isSortable: true,
  },
  {
    name: 'cmdletsGenerated',
    label: 'Cmdlets Generated',
    isSortable: true,
  },
  {
    name: 'state',
    label: 'Status',
    isSortable: true,
    width: '150px',
    filterRenderer: () => {
      return (
        <TableMultiSelectFilter<AdhRuleFilter, AdhRuleState> filterName="ruleStates" options={ruleStatesOptions} />
      );
    },
    filterName: 'ruleStates',
    schema: {
      cellRenderer: (rule: AdhRule) => {
        return <RuleStatusCell rule={rule} />;
      },
    },
  },
  {
    name: 'actions',
    label: 'Actions',
    headerAlign: 'center',
    width: '120px',
    schema: {
      cellRenderer: (rule: AdhRule) => <RuleActionsCell rule={rule} />,
    },
  },
];
