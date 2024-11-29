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
declare module 'monaco-editor/esm/vs/editor/common/services/languageFeatures.js' {
  export const ILanguageFeaturesService: { documentSymbolProvider: unknown };
}

declare module 'monaco-editor/esm/vs/editor/common/modelLineProjectionData.js' {
  export class InjectedText {
    constructor(public readonly options: InjectedTextOptions) {}
  }
}

declare module 'monaco-editor/esm/vs/editor/contrib/documentSymbols/browser/outlineModel.js' {
  import { type editor, type languages } from 'monaco-editor';

  interface TreeElement {
    id: string;
    parent?: TreeElement;
    symbol: languages.DocumentSymbol;
    children: Map<number, TreeElement>;
  }

  export abstract class OutlineModel {
    static create(registry: unknown, model: editor.ITextModel): Promise<OutlineModel>;

    children: Map<number, TreeElement>;
    asListOfDocumentSymbols(): languages.DocumentSymbol[];
  }
}

declare module 'monaco-editor/esm/vs/editor/standalone/browser/standaloneServices.js' {
  export const StandaloneServices: {
    get: (id: unknown) => { documentSymbolProvider: unknown };
  };
}
