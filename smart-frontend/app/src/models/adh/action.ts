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
import type { DateRange, SerializedDate } from '@models/dateRange';

export enum AdhActionSource {
  Rule = 'RULE',
  User = 'USER',
}

export enum AdhActionState {
  Running = 'RUNNING',
  Successful = 'SUCCESSFUL',
  Failed = 'FAILED',
}

export interface AdhAction {
  id: number;
  cmdletId: number;
  textRepresentation: string;
  execHost?: string | null;
  submissionTime: number;
  completionTime?: number | null;
  state: AdhActionState;
  source: AdhActionSource;
  log?: string;
}

export interface AdhActionDetails extends AdhAction {
  result: string;
}

export interface AdhActionsFilter {
  textRepresentationLike?: string;
  submissionTime?: DateRange<SerializedDate>;
  hosts?: string[];
  states?: AdhActionState[];
  sources?: AdhActionSource[];
  completionTime?: DateRange<SerializedDate>;
}
