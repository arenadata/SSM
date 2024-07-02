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
import ClusterInfoCards from './ClusterInfoCards/ClusterInfoCards';
import ClusterInfoToolbar from './ClusterInfoToolbar/ClusterInfoToolbar';
import ClusterInfoTable from './ClusterInfoTable/ClusterInfoTable';
import ClusterInfoFilesTable from './ClusterInfoFilesTable/ClusterInfoFilesTable';
import { FlexGroup, Title } from '@uikit';
import { useRequestClusterInfo } from './useRequestClusterInfo';
import { Title } from '@uikit';
import ClusterFiles from './ClusterFiles/ClusterFiles';

const ClusterInfoPage: React.FC = () => {
  useRequestClusterInfo();

  return (
    <div>
      <FlexGroup gap="20px">
        <Title variant="h1">Cluster Info</Title>
      </FlexGroup>
      <ClusterInfoCards />
      <ClusterInfoToolbar />
      <ClusterInfoTable />
      <ClusterInfoFilesTable />
      <ClusterFiles />
    </div>
  );
};

export default ClusterInfoPage;
