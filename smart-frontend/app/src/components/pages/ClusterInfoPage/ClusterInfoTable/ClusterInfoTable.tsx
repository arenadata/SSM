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
import React from 'react';
import Table from '@uikit/Table/Table';
import { useDispatch, useStore } from '@hooks';
import { isShowSpinner } from '@uikit/Table/Table.utils';
import TableRow from '@uikit/Table/TableRow/TableRow';
import TableCellsRenderer from '@uikit/Table/TableCell/TableCellsRenderer';
import { setClusterNodesFilter, setClusterNodesSortParams } from '@store/adh/cluster/clusterNodesTableSlice';
import type { SortParams } from '@models/table';
import type { AdhClusterNodesFilter } from '@models/adh';
import { clusterNodesColumns } from './ClusterInfoTable.schema';

const ClusterInfoTable: React.FC = () => {
  const dispatch = useDispatch();

  const nodes = useStore(({ adh }) => adh.clusterNodes.nodes);
  const isLoading = useStore(({ adh }) => isShowSpinner(adh.clusterNodes.loadState));

  const filter = useStore(({ adh }) => adh.clusterNodesTable.filter);
  const sortParams = useStore(({ adh }) => adh.clusterNodesTable.sortParams);

  const handleFiltering = (filter: Partial<AdhClusterNodesFilter>) => {
    dispatch(setClusterNodesFilter(filter));
  };
  const handleSorting = (sortParams: SortParams) => {
    dispatch(setClusterNodesSortParams(sortParams));
  };

  return (
    <Table
      isLoading={isLoading}
      columns={clusterNodesColumns}
      filter={filter}
      onFiltering={handleFiltering}
      sortParams={sortParams}
      onSorting={handleSorting}
      dataTest="cluster-info-table"
    >
      {nodes.map((node) => (
        <TableRow key={node.id}>
          <TableCellsRenderer model={node} />
        </TableRow>
      ))}
    </Table>
  );
};

export default ClusterInfoTable;
