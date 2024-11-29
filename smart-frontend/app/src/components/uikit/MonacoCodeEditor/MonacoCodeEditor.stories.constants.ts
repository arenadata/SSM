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

/* eslint-disable spellcheck/spell-checker */

export const schema = {
  type: 'object',
  required: ['some_field'],
  properties: {
    some_enum: {
      type: 'string',
      enum: ['up', 'down', 'left', 'right'],
    },
    some_optional: {
      oneOf: [
        {
          type: 'boolean',
          title: '',
          description: '',
          default: false,
          readOnly: false,
          adcmMeta: {
            isAdvanced: false,
            isInvisible: false,
            activation: null,
            synchronization: null,
            isSecret: false,
            stringExtra: null,
            enumExtra: null,
          },
        },
        {
          type: 'null',
        },
      ],
    },
    some_field: {
      type: 'string',
      description: 'some field. Required',
      adcmMeta: {
        isAdvanced: false,
        isInvisible: false,
        activation: null,
        synchronization: null,
        isSecret: false,
        stringExtra: null,
        enumExtra: null,
      },
      readOnly: true,
    },
    some_structure: {
      type: 'object',
      default: {},
      readOnly: true,
      adcmMeta: {
        isAdvanced: false,
        isInvisible: false,
        activation: null,
        synchronization: null,

        isSecret: false,
        stringExtra: null,
        enumExtra: null,
      },
      additionalProperties: false,
      properties: {
        key1: {
          type: 'string',
          adcmMeta: {
            isAdvanced: false,
            isInvisible: false,
            activation: null,
            synchronization: null,
            isSecret: false,
            stringExtra: null,
            enumExtra: null,
          },
          readOnly: true,
        },
      },
    },
    some_map: {
      type: 'object',
      default: {},
      readOnly: true,
      adcmMeta: {
        isAdvanced: false,
        isInvisible: false,
        activation: null,
        synchronization: null,
        isSecret: false,
        stringExtra: null,
        enumExtra: null,
      },
      additionalProperties: true,
      properties: {},
    },
    some_array: {
      type: 'array',
      default: [],
      description: 'some description',
      readOnly: true,
      adcmMeta: {
        isAdvanced: false,
        isInvisible: false,
        activation: null,
        synchronization: null,

        isSecret: false,
        stringExtra: null,
        enumExtra: null,
      },
      items: {
        type: 'object',
        adcmMeta: {
          isAdvanced: false,
          isInvisible: false,
          activation: null,
          synchronization: null,
          isSecret: false,
          stringExtra: null,
          enumExtra: null,
        },
        readOnly: true,
        required: ['field1', 'field2'],
        properties: {
          field1: {
            type: 'string',
            adcmMeta: {
              isAdvanced: false,
              isInvisible: false,
              activation: null,
              synchronization: null,
              isSecret: false,
              stringExtra: null,
              enumExtra: null,
            },
            readOnly: false,
          },
          field2: {
            type: 'number',
            description: 'field2 description',
            minimum: 10,
            default: 55,
            maximum: 100,
            adcmMeta: {
              isAdvanced: false,
              isInvisible: false,
              activation: null,
              synchronization: null,
              isSecret: false,
              stringExtra: null,
              enumExtra: null,
            },
            readOnly: false,
          },
        },
      },
    },
  },
};

export const jsonText = `{
  "some_field": "lorem",
  "some_structure": {
    "key1": "value1"
  },
  "some_map": {
    "mapEntry1": "123",
    "mapEntry2": "456"
  },
  "some_array": [{ "field1": "value" }]
}`;
