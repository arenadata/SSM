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
import type { AdhRule, AdhRuleFilter } from '@models/adh';
import type { PaginationParams, SortParams } from '@models/table';
import type { PaginateCollection } from '@models/collection';
import { prepareNamedDateRange, prepareQueryParams } from '@utils/requestUtils';
import { httpClient } from '@api/httpClient';
import qs from 'qs';

export class AdhRulesApi {
  public static async getRules(
    { submissionTime, lastActivationTime, ...filter }: AdhRuleFilter,
    sortParams?: SortParams,
    paginationParams?: PaginationParams,
  ): Promise<PaginateCollection<AdhRule>> {
    const queryParams = prepareQueryParams(
      {
        ...filter,
        ...prepareNamedDateRange(submissionTime, 'submissionTime'),
        ...prepareNamedDateRange(lastActivationTime, 'lastActivationTime'),
      },
      sortParams,
      paginationParams,
    );

    const query = qs.stringify(queryParams, { arrayFormat: 'repeat' });

    const response = await httpClient.get<PaginateCollection<AdhRule>>(`/api/v2/rules?${query}`);

    return response.data;
  }

  public static async createRule(text: string) {
    const response = await httpClient.post('/api/v2/rules', {
      rule: text,
    });

    return response.data;
  }

  public static async deleteRule(id: number) {
    const response = await httpClient.delete(`/api/v2/rules/${id}`);

    return response.data;
  }

  public static async startRule(id: number) {
    const response = await httpClient.post(`/api/v2/rules/${id}/start`);

    return response.data;
  }

  public static async stopRule(id: number) {
    const response = await httpClient.post(`/api/v2/rules/${id}/stop`);

    return response.data;
  }
}
