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
import type { AdhFileInfo, AdhFileInfoFilter, AdhCachedFileInfo, AdhCachedFileInfoFilter } from '@models/adh';
import type { PaginationParams, SortParams } from '@models/table';
import type { PaginateCollection } from '@models/collection';
import { prepareNamedDateRange, prepareQueryParams } from '@utils/requestUtils';
import { httpClient } from '@api/httpClient';
import qs from 'qs';

export class AdhFilesApi {
  public static async getHottestFiles(
    { lastAccessedTime, ...filter }: AdhFileInfoFilter,
    sortParams: SortParams,
    paginationParams: PaginationParams,
  ): Promise<PaginateCollection<AdhFileInfo>> {
    const queryParams = prepareQueryParams(
      {
        ...filter,
        ...prepareNamedDateRange(lastAccessedTime, 'lastAccessedTime'),
      },
      sortParams,
      paginationParams,
    );

    const query = qs.stringify(queryParams);
    const response = await httpClient.get<PaginateCollection<AdhFileInfo>>(`/api/v2/files/access-counts?${query}`);

    return response.data;
  }

  public static async getCachedFiles(
    { lastAccessedTime, cachedTime, ...filter }: AdhCachedFileInfoFilter,
    sortParams: SortParams,
    paginationParams: PaginationParams,
  ): Promise<PaginateCollection<AdhCachedFileInfo>> {
    const queryParams = prepareQueryParams(
      {
        ...filter,
        ...prepareNamedDateRange(lastAccessedTime, 'lastAccessedTime'),
        ...prepareNamedDateRange(cachedTime, 'cachedTime'),
      },
      sortParams,
      paginationParams,
    );

    const query = qs.stringify(queryParams);
    const response = await httpClient.get<PaginateCollection<AdhCachedFileInfo>>(`/api/v2/files/cached?${query}`);

    return response.data;
  }
}
