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

export enum AdhAuditObjectType {
  Rule = 'RULE',
  Cmdlet = 'CMDLET',
  Cluster = 'CLUSTER',
  ReplicationPolicy = 'REPLICATION_POLICY',
}

export enum AdhAuditOperation {
  Create = 'CREATE',
  Delete = 'DELETE',
  Start = 'START',
  Stop = 'STOP',
}

export enum AdhAuditEventResult {
  Success = 'SUCCESS',
  Failure = 'FAILURE',
}

export interface AdhAuditEvent {
  id: number;
  username: string;
  timestamp: number;
  objectType: AdhAuditObjectType;
  objectId: number;
  operation: AdhAuditOperation;
  result: AdhAuditEventResult;
}

export interface AdhAuditEventsFilter {
  usernameLike?: string;
  eventTime?: DateRange<SerializedDate>;
  objectTypes?: AdhAuditObjectType[];
  objectIds?: number[];
  operations?: AdhAuditOperation[];
  results?: AdhAuditEventResult[];
}
