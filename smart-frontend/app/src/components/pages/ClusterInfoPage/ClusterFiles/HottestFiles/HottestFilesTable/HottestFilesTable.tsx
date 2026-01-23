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
import { hottestFilesColumns } from './HottestFilesTable.schema';
import { useDispatch, useStore } from '@hooks';
import { isShowSpinner } from '@uikit/Table/Table.utils';
import TableRow from '@uikit/Table/TableRow/TableRow';
import TableCellsRenderer from '@uikit/Table/TableCell/TableCellsRenderer';
import { setHottestFilesFilter, setHottestFilesSortParams } from '@store/adh/hottestFiles/hottestFilesTableSlice';
import type { SortParams } from '@models/table';
import type { AdhFileInfoFilter } from '@models/adh';

const HottestFilesTable: React.FC = () => {
  const dispatch = useDispatch();
  const hottestFiles = useStore(({ adh }) => adh.hottestFiles.hottestFiles);
  const isLoading = useStore(({ adh }) => isShowSpinner(adh.hottestFiles.loadState));

  const filter = useStore(({ adh }) => adh.hottestFilesTable.filter);
  const sortParams = useStore(({ adh }) => adh.hottestFilesTable.sortParams);

  const handleFiltering = (filter: Partial<AdhFileInfoFilter>) => {
    dispatch(setHottestFilesFilter(filter));
  };
  const handleSorting = (sortParams: SortParams) => {
    dispatch(setHottestFilesSortParams(sortParams));
  };

  return (
    <Table
      isLoading={isLoading}
      columns={hottestFilesColumns}
      filter={filter}
      onFiltering={handleFiltering}
      sortParams={sortParams}
      onSorting={handleSorting}
      dataTest="hottest-files-table"
    >
      {hottestFiles.map((file) => (
        <TableRow key={file.id}>
          <TableCellsRenderer model={file} />
        </TableRow>
      ))}
    </Table>
  );
};

export default HottestFilesTable;
