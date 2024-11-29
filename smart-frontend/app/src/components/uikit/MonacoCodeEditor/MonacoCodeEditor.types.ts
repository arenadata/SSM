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

import * as monaco from 'monaco-editor/esm/vs/editor/editor.api';
import { Range, languages, MarkerSeverity } from 'monaco-editor';
import { type ReactNode } from 'react';

export { monaco, Range, languages, MarkerSeverity };
export type ITextModel = monaco.editor.ITextModel;
export type IMarker = monaco.editor.IMarker;
export type IPosition = monaco.IPosition;
export type Position = monaco.Position;
export type IRange = monaco.IRange;
export type IDisposable = monaco.IDisposable;
export type IStandaloneCodeEditor = monaco.editor.IStandaloneCodeEditor;
export type IGlyphMarginWidget = monaco.editor.IGlyphMarginWidget;
export type IEditorDecorationsCollection = monaco.editor.IEditorDecorationsCollection;
export type IModelDecorationOptions = monaco.editor.IModelDecorationOptions;
export type IModelDeltaDecoration = monaco.editor.IModelDeltaDecoration;
export type InjectedTextOptions = monaco.editor.InjectedTextOptions;
export type IEditorMouseEvent = monaco.editor.IEditorMouseEvent;
export type IPartialEditorMouseEvent = monaco.editor.IPartialEditorMouseEvent;
export type IMouseTarget = monaco.editor.IMouseTarget;
export type IContentWidget = monaco.editor.IContentWidget;
export type ILayoutWidget = monaco.editor.IOverlayWidget;
export type IContentWidgetPosition = monaco.editor.IContentWidgetPosition;
export const ContentWidgetPositionPreference = monaco.editor.ContentWidgetPositionPreference;
export const OverlayWidgetPositionPreference = monaco.editor.OverlayWidgetPositionPreference;

export type ValidationResult = {
  owner: string;
  markers: IMarker[];
};

export type SymbolsDictionary = { [path: string]: languages.DocumentSymbol };

export interface MonacoCodeEditorContentWidget {
  type: 'content';
  getWidget(): IContentWidget;
  renderWidget(): ReactNode;
}

export interface MonacoCodeEditorOverlayWidget {
  type: 'overlay';
  getWidget(): ILayoutWidget;
  renderWidget(): ReactNode;
}

export type MonacoCodeEditorWidget = MonacoCodeEditorContentWidget | MonacoCodeEditorOverlayWidget;

export type MonacoCodeEditorAcceptedLanguages = 'json' | 'ssmrule';
