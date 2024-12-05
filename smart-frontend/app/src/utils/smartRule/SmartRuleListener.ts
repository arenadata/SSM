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

// Generated from SmartRule.g4 by ANTLR 4.13.2

import {ParseTreeListener} from "antlr4";


import { RuleLineContext } from "./SmartRuleParser.js";
import { CommentLineContext } from "./SmartRuleParser.js";
import { ObjTypeOnlyContext } from "./SmartRuleParser.js";
import { ObjTypeWithContext } from "./SmartRuleParser.js";
import { TriTimePointContext } from "./SmartRuleParser.js";
import { TriCycleContext } from "./SmartRuleParser.js";
import { TriFileEventContext } from "./SmartRuleParser.js";
import { TriOnceContext } from "./SmartRuleParser.js";
import { DuringexprContext } from "./SmartRuleParser.js";
import { ObjfilterContext } from "./SmartRuleParser.js";
import { ConditionsContext } from "./SmartRuleParser.js";
import { BvAndORContext } from "./SmartRuleParser.js";
import { BvIdContext } from "./SmartRuleParser.js";
import { BvNotContext } from "./SmartRuleParser.js";
import { BvCompareexprContext } from "./SmartRuleParser.js";
import { BvCurveContext } from "./SmartRuleParser.js";
import { CmpIdLongContext } from "./SmartRuleParser.js";
import { CmpIdStringContext } from "./SmartRuleParser.js";
import { CmpIdStringMatchesContext } from "./SmartRuleParser.js";
import { CmpTimeintvalTimeintvalContext } from "./SmartRuleParser.js";
import { CmpTimepointTimePointContext } from "./SmartRuleParser.js";
import { TieTiIdExprContext } from "./SmartRuleParser.js";
import { TieTpExprContext } from "./SmartRuleParser.js";
import { TieConstContext } from "./SmartRuleParser.js";
import { TieTiExprContext } from "./SmartRuleParser.js";
import { TieCurvesContext } from "./SmartRuleParser.js";
import { TpeNowContext } from "./SmartRuleParser.js";
import { TpeTimeConstContext } from "./SmartRuleParser.js";
import { TpeTimeExprContext } from "./SmartRuleParser.js";
import { TpeCurvesContext } from "./SmartRuleParser.js";
import { TpeTimeIdContext } from "./SmartRuleParser.js";
import { CommonexprContext } from "./SmartRuleParser.js";
import { NumricexprIdContext } from "./SmartRuleParser.js";
import { NumricexprCurveContext } from "./SmartRuleParser.js";
import { NumricexprAddContext } from "./SmartRuleParser.js";
import { NumricexprMulContext } from "./SmartRuleParser.js";
import { NumricexprLongContext } from "./SmartRuleParser.js";
import { StrPlusContext } from "./SmartRuleParser.js";
import { StrOrdStringContext } from "./SmartRuleParser.js";
import { StrIDContext } from "./SmartRuleParser.js";
import { StrCurveContext } from "./SmartRuleParser.js";
import { StrTimePointStrContext } from "./SmartRuleParser.js";
import { CmdletContext } from "./SmartRuleParser.js";
import { IdAttContext } from "./SmartRuleParser.js";
import { IdObjAttContext } from "./SmartRuleParser.js";
import { IdAttParaContext } from "./SmartRuleParser.js";
import { IdObjAttParaContext } from "./SmartRuleParser.js";
import { OprContext } from "./SmartRuleParser.js";
import { FileEventContext } from "./SmartRuleParser.js";
import { ConstLongContext } from "./SmartRuleParser.js";
import { ConstStringContext } from "./SmartRuleParser.js";
import { ConstTimeInvervalContext } from "./SmartRuleParser.js";
import { ConstTimePointContext } from "./SmartRuleParser.js";


/**
 * This interface defines a complete listener for a parse tree produced by
 * `SmartRuleParser`.
 */
export default class SmartRuleListener extends ParseTreeListener {
	/**
	 * Enter a parse tree produced by the `ruleLine`
	 * labeled alternative in `SmartRuleParser.ssmrule`.
	 * @param ctx the parse tree
	 */
	enterRuleLine?: (ctx: RuleLineContext) => void;
	/**
	 * Exit a parse tree produced by the `ruleLine`
	 * labeled alternative in `SmartRuleParser.ssmrule`.
	 * @param ctx the parse tree
	 */
	exitRuleLine?: (ctx: RuleLineContext) => void;
	/**
	 * Enter a parse tree produced by the `commentLine`
	 * labeled alternative in `SmartRuleParser.ssmrule`.
	 * @param ctx the parse tree
	 */
	enterCommentLine?: (ctx: CommentLineContext) => void;
	/**
	 * Exit a parse tree produced by the `commentLine`
	 * labeled alternative in `SmartRuleParser.ssmrule`.
	 * @param ctx the parse tree
	 */
	exitCommentLine?: (ctx: CommentLineContext) => void;
	/**
	 * Enter a parse tree produced by the `objTypeOnly`
	 * labeled alternative in `SmartRuleParser.object`.
	 * @param ctx the parse tree
	 */
	enterObjTypeOnly?: (ctx: ObjTypeOnlyContext) => void;
	/**
	 * Exit a parse tree produced by the `objTypeOnly`
	 * labeled alternative in `SmartRuleParser.object`.
	 * @param ctx the parse tree
	 */
	exitObjTypeOnly?: (ctx: ObjTypeOnlyContext) => void;
	/**
	 * Enter a parse tree produced by the `objTypeWith`
	 * labeled alternative in `SmartRuleParser.object`.
	 * @param ctx the parse tree
	 */
	enterObjTypeWith?: (ctx: ObjTypeWithContext) => void;
	/**
	 * Exit a parse tree produced by the `objTypeWith`
	 * labeled alternative in `SmartRuleParser.object`.
	 * @param ctx the parse tree
	 */
	exitObjTypeWith?: (ctx: ObjTypeWithContext) => void;
	/**
	 * Enter a parse tree produced by the `triTimePoint`
	 * labeled alternative in `SmartRuleParser.trigger`.
	 * @param ctx the parse tree
	 */
	enterTriTimePoint?: (ctx: TriTimePointContext) => void;
	/**
	 * Exit a parse tree produced by the `triTimePoint`
	 * labeled alternative in `SmartRuleParser.trigger`.
	 * @param ctx the parse tree
	 */
	exitTriTimePoint?: (ctx: TriTimePointContext) => void;
	/**
	 * Enter a parse tree produced by the `triCycle`
	 * labeled alternative in `SmartRuleParser.trigger`.
	 * @param ctx the parse tree
	 */
	enterTriCycle?: (ctx: TriCycleContext) => void;
	/**
	 * Exit a parse tree produced by the `triCycle`
	 * labeled alternative in `SmartRuleParser.trigger`.
	 * @param ctx the parse tree
	 */
	exitTriCycle?: (ctx: TriCycleContext) => void;
	/**
	 * Enter a parse tree produced by the `triFileEvent`
	 * labeled alternative in `SmartRuleParser.trigger`.
	 * @param ctx the parse tree
	 */
	enterTriFileEvent?: (ctx: TriFileEventContext) => void;
	/**
	 * Exit a parse tree produced by the `triFileEvent`
	 * labeled alternative in `SmartRuleParser.trigger`.
	 * @param ctx the parse tree
	 */
	exitTriFileEvent?: (ctx: TriFileEventContext) => void;
	/**
	 * Enter a parse tree produced by the `triOnce`
	 * labeled alternative in `SmartRuleParser.trigger`.
	 * @param ctx the parse tree
	 */
	enterTriOnce?: (ctx: TriOnceContext) => void;
	/**
	 * Exit a parse tree produced by the `triOnce`
	 * labeled alternative in `SmartRuleParser.trigger`.
	 * @param ctx the parse tree
	 */
	exitTriOnce?: (ctx: TriOnceContext) => void;
	/**
	 * Enter a parse tree produced by `SmartRuleParser.duringexpr`.
	 * @param ctx the parse tree
	 */
	enterDuringexpr?: (ctx: DuringexprContext) => void;
	/**
	 * Exit a parse tree produced by `SmartRuleParser.duringexpr`.
	 * @param ctx the parse tree
	 */
	exitDuringexpr?: (ctx: DuringexprContext) => void;
	/**
	 * Enter a parse tree produced by `SmartRuleParser.objfilter`.
	 * @param ctx the parse tree
	 */
	enterObjfilter?: (ctx: ObjfilterContext) => void;
	/**
	 * Exit a parse tree produced by `SmartRuleParser.objfilter`.
	 * @param ctx the parse tree
	 */
	exitObjfilter?: (ctx: ObjfilterContext) => void;
	/**
	 * Enter a parse tree produced by `SmartRuleParser.conditions`.
	 * @param ctx the parse tree
	 */
	enterConditions?: (ctx: ConditionsContext) => void;
	/**
	 * Exit a parse tree produced by `SmartRuleParser.conditions`.
	 * @param ctx the parse tree
	 */
	exitConditions?: (ctx: ConditionsContext) => void;
	/**
	 * Enter a parse tree produced by the `bvAndOR`
	 * labeled alternative in `SmartRuleParser.boolvalue`.
	 * @param ctx the parse tree
	 */
	enterBvAndOR?: (ctx: BvAndORContext) => void;
	/**
	 * Exit a parse tree produced by the `bvAndOR`
	 * labeled alternative in `SmartRuleParser.boolvalue`.
	 * @param ctx the parse tree
	 */
	exitBvAndOR?: (ctx: BvAndORContext) => void;
	/**
	 * Enter a parse tree produced by the `bvId`
	 * labeled alternative in `SmartRuleParser.boolvalue`.
	 * @param ctx the parse tree
	 */
	enterBvId?: (ctx: BvIdContext) => void;
	/**
	 * Exit a parse tree produced by the `bvId`
	 * labeled alternative in `SmartRuleParser.boolvalue`.
	 * @param ctx the parse tree
	 */
	exitBvId?: (ctx: BvIdContext) => void;
	/**
	 * Enter a parse tree produced by the `bvNot`
	 * labeled alternative in `SmartRuleParser.boolvalue`.
	 * @param ctx the parse tree
	 */
	enterBvNot?: (ctx: BvNotContext) => void;
	/**
	 * Exit a parse tree produced by the `bvNot`
	 * labeled alternative in `SmartRuleParser.boolvalue`.
	 * @param ctx the parse tree
	 */
	exitBvNot?: (ctx: BvNotContext) => void;
	/**
	 * Enter a parse tree produced by the `bvCompareexpr`
	 * labeled alternative in `SmartRuleParser.boolvalue`.
	 * @param ctx the parse tree
	 */
	enterBvCompareexpr?: (ctx: BvCompareexprContext) => void;
	/**
	 * Exit a parse tree produced by the `bvCompareexpr`
	 * labeled alternative in `SmartRuleParser.boolvalue`.
	 * @param ctx the parse tree
	 */
	exitBvCompareexpr?: (ctx: BvCompareexprContext) => void;
	/**
	 * Enter a parse tree produced by the `bvCurve`
	 * labeled alternative in `SmartRuleParser.boolvalue`.
	 * @param ctx the parse tree
	 */
	enterBvCurve?: (ctx: BvCurveContext) => void;
	/**
	 * Exit a parse tree produced by the `bvCurve`
	 * labeled alternative in `SmartRuleParser.boolvalue`.
	 * @param ctx the parse tree
	 */
	exitBvCurve?: (ctx: BvCurveContext) => void;
	/**
	 * Enter a parse tree produced by the `cmpIdLong`
	 * labeled alternative in `SmartRuleParser.compareexpr`.
	 * @param ctx the parse tree
	 */
	enterCmpIdLong?: (ctx: CmpIdLongContext) => void;
	/**
	 * Exit a parse tree produced by the `cmpIdLong`
	 * labeled alternative in `SmartRuleParser.compareexpr`.
	 * @param ctx the parse tree
	 */
	exitCmpIdLong?: (ctx: CmpIdLongContext) => void;
	/**
	 * Enter a parse tree produced by the `cmpIdString`
	 * labeled alternative in `SmartRuleParser.compareexpr`.
	 * @param ctx the parse tree
	 */
	enterCmpIdString?: (ctx: CmpIdStringContext) => void;
	/**
	 * Exit a parse tree produced by the `cmpIdString`
	 * labeled alternative in `SmartRuleParser.compareexpr`.
	 * @param ctx the parse tree
	 */
	exitCmpIdString?: (ctx: CmpIdStringContext) => void;
	/**
	 * Enter a parse tree produced by the `cmpIdStringMatches`
	 * labeled alternative in `SmartRuleParser.compareexpr`.
	 * @param ctx the parse tree
	 */
	enterCmpIdStringMatches?: (ctx: CmpIdStringMatchesContext) => void;
	/**
	 * Exit a parse tree produced by the `cmpIdStringMatches`
	 * labeled alternative in `SmartRuleParser.compareexpr`.
	 * @param ctx the parse tree
	 */
	exitCmpIdStringMatches?: (ctx: CmpIdStringMatchesContext) => void;
	/**
	 * Enter a parse tree produced by the `cmpTimeintvalTimeintval`
	 * labeled alternative in `SmartRuleParser.compareexpr`.
	 * @param ctx the parse tree
	 */
	enterCmpTimeintvalTimeintval?: (ctx: CmpTimeintvalTimeintvalContext) => void;
	/**
	 * Exit a parse tree produced by the `cmpTimeintvalTimeintval`
	 * labeled alternative in `SmartRuleParser.compareexpr`.
	 * @param ctx the parse tree
	 */
	exitCmpTimeintvalTimeintval?: (ctx: CmpTimeintvalTimeintvalContext) => void;
	/**
	 * Enter a parse tree produced by the `cmpTimepointTimePoint`
	 * labeled alternative in `SmartRuleParser.compareexpr`.
	 * @param ctx the parse tree
	 */
	enterCmpTimepointTimePoint?: (ctx: CmpTimepointTimePointContext) => void;
	/**
	 * Exit a parse tree produced by the `cmpTimepointTimePoint`
	 * labeled alternative in `SmartRuleParser.compareexpr`.
	 * @param ctx the parse tree
	 */
	exitCmpTimepointTimePoint?: (ctx: CmpTimepointTimePointContext) => void;
	/**
	 * Enter a parse tree produced by the `tieTiIdExpr`
	 * labeled alternative in `SmartRuleParser.timeintvalexpr`.
	 * @param ctx the parse tree
	 */
	enterTieTiIdExpr?: (ctx: TieTiIdExprContext) => void;
	/**
	 * Exit a parse tree produced by the `tieTiIdExpr`
	 * labeled alternative in `SmartRuleParser.timeintvalexpr`.
	 * @param ctx the parse tree
	 */
	exitTieTiIdExpr?: (ctx: TieTiIdExprContext) => void;
	/**
	 * Enter a parse tree produced by the `tieTpExpr`
	 * labeled alternative in `SmartRuleParser.timeintvalexpr`.
	 * @param ctx the parse tree
	 */
	enterTieTpExpr?: (ctx: TieTpExprContext) => void;
	/**
	 * Exit a parse tree produced by the `tieTpExpr`
	 * labeled alternative in `SmartRuleParser.timeintvalexpr`.
	 * @param ctx the parse tree
	 */
	exitTieTpExpr?: (ctx: TieTpExprContext) => void;
	/**
	 * Enter a parse tree produced by the `tieConst`
	 * labeled alternative in `SmartRuleParser.timeintvalexpr`.
	 * @param ctx the parse tree
	 */
	enterTieConst?: (ctx: TieConstContext) => void;
	/**
	 * Exit a parse tree produced by the `tieConst`
	 * labeled alternative in `SmartRuleParser.timeintvalexpr`.
	 * @param ctx the parse tree
	 */
	exitTieConst?: (ctx: TieConstContext) => void;
	/**
	 * Enter a parse tree produced by the `tieTiExpr`
	 * labeled alternative in `SmartRuleParser.timeintvalexpr`.
	 * @param ctx the parse tree
	 */
	enterTieTiExpr?: (ctx: TieTiExprContext) => void;
	/**
	 * Exit a parse tree produced by the `tieTiExpr`
	 * labeled alternative in `SmartRuleParser.timeintvalexpr`.
	 * @param ctx the parse tree
	 */
	exitTieTiExpr?: (ctx: TieTiExprContext) => void;
	/**
	 * Enter a parse tree produced by the `tieCurves`
	 * labeled alternative in `SmartRuleParser.timeintvalexpr`.
	 * @param ctx the parse tree
	 */
	enterTieCurves?: (ctx: TieCurvesContext) => void;
	/**
	 * Exit a parse tree produced by the `tieCurves`
	 * labeled alternative in `SmartRuleParser.timeintvalexpr`.
	 * @param ctx the parse tree
	 */
	exitTieCurves?: (ctx: TieCurvesContext) => void;
	/**
	 * Enter a parse tree produced by the `tpeNow`
	 * labeled alternative in `SmartRuleParser.timepointexpr`.
	 * @param ctx the parse tree
	 */
	enterTpeNow?: (ctx: TpeNowContext) => void;
	/**
	 * Exit a parse tree produced by the `tpeNow`
	 * labeled alternative in `SmartRuleParser.timepointexpr`.
	 * @param ctx the parse tree
	 */
	exitTpeNow?: (ctx: TpeNowContext) => void;
	/**
	 * Enter a parse tree produced by the `tpeTimeConst`
	 * labeled alternative in `SmartRuleParser.timepointexpr`.
	 * @param ctx the parse tree
	 */
	enterTpeTimeConst?: (ctx: TpeTimeConstContext) => void;
	/**
	 * Exit a parse tree produced by the `tpeTimeConst`
	 * labeled alternative in `SmartRuleParser.timepointexpr`.
	 * @param ctx the parse tree
	 */
	exitTpeTimeConst?: (ctx: TpeTimeConstContext) => void;
	/**
	 * Enter a parse tree produced by the `tpeTimeExpr`
	 * labeled alternative in `SmartRuleParser.timepointexpr`.
	 * @param ctx the parse tree
	 */
	enterTpeTimeExpr?: (ctx: TpeTimeExprContext) => void;
	/**
	 * Exit a parse tree produced by the `tpeTimeExpr`
	 * labeled alternative in `SmartRuleParser.timepointexpr`.
	 * @param ctx the parse tree
	 */
	exitTpeTimeExpr?: (ctx: TpeTimeExprContext) => void;
	/**
	 * Enter a parse tree produced by the `tpeCurves`
	 * labeled alternative in `SmartRuleParser.timepointexpr`.
	 * @param ctx the parse tree
	 */
	enterTpeCurves?: (ctx: TpeCurvesContext) => void;
	/**
	 * Exit a parse tree produced by the `tpeCurves`
	 * labeled alternative in `SmartRuleParser.timepointexpr`.
	 * @param ctx the parse tree
	 */
	exitTpeCurves?: (ctx: TpeCurvesContext) => void;
	/**
	 * Enter a parse tree produced by the `tpeTimeId`
	 * labeled alternative in `SmartRuleParser.timepointexpr`.
	 * @param ctx the parse tree
	 */
	enterTpeTimeId?: (ctx: TpeTimeIdContext) => void;
	/**
	 * Exit a parse tree produced by the `tpeTimeId`
	 * labeled alternative in `SmartRuleParser.timepointexpr`.
	 * @param ctx the parse tree
	 */
	exitTpeTimeId?: (ctx: TpeTimeIdContext) => void;
	/**
	 * Enter a parse tree produced by `SmartRuleParser.commonexpr`.
	 * @param ctx the parse tree
	 */
	enterCommonexpr?: (ctx: CommonexprContext) => void;
	/**
	 * Exit a parse tree produced by `SmartRuleParser.commonexpr`.
	 * @param ctx the parse tree
	 */
	exitCommonexpr?: (ctx: CommonexprContext) => void;
	/**
	 * Enter a parse tree produced by the `numricexprId`
	 * labeled alternative in `SmartRuleParser.numricexpr`.
	 * @param ctx the parse tree
	 */
	enterNumricexprId?: (ctx: NumricexprIdContext) => void;
	/**
	 * Exit a parse tree produced by the `numricexprId`
	 * labeled alternative in `SmartRuleParser.numricexpr`.
	 * @param ctx the parse tree
	 */
	exitNumricexprId?: (ctx: NumricexprIdContext) => void;
	/**
	 * Enter a parse tree produced by the `numricexprCurve`
	 * labeled alternative in `SmartRuleParser.numricexpr`.
	 * @param ctx the parse tree
	 */
	enterNumricexprCurve?: (ctx: NumricexprCurveContext) => void;
	/**
	 * Exit a parse tree produced by the `numricexprCurve`
	 * labeled alternative in `SmartRuleParser.numricexpr`.
	 * @param ctx the parse tree
	 */
	exitNumricexprCurve?: (ctx: NumricexprCurveContext) => void;
	/**
	 * Enter a parse tree produced by the `numricexprAdd`
	 * labeled alternative in `SmartRuleParser.numricexpr`.
	 * @param ctx the parse tree
	 */
	enterNumricexprAdd?: (ctx: NumricexprAddContext) => void;
	/**
	 * Exit a parse tree produced by the `numricexprAdd`
	 * labeled alternative in `SmartRuleParser.numricexpr`.
	 * @param ctx the parse tree
	 */
	exitNumricexprAdd?: (ctx: NumricexprAddContext) => void;
	/**
	 * Enter a parse tree produced by the `numricexprMul`
	 * labeled alternative in `SmartRuleParser.numricexpr`.
	 * @param ctx the parse tree
	 */
	enterNumricexprMul?: (ctx: NumricexprMulContext) => void;
	/**
	 * Exit a parse tree produced by the `numricexprMul`
	 * labeled alternative in `SmartRuleParser.numricexpr`.
	 * @param ctx the parse tree
	 */
	exitNumricexprMul?: (ctx: NumricexprMulContext) => void;
	/**
	 * Enter a parse tree produced by the `numricexprLong`
	 * labeled alternative in `SmartRuleParser.numricexpr`.
	 * @param ctx the parse tree
	 */
	enterNumricexprLong?: (ctx: NumricexprLongContext) => void;
	/**
	 * Exit a parse tree produced by the `numricexprLong`
	 * labeled alternative in `SmartRuleParser.numricexpr`.
	 * @param ctx the parse tree
	 */
	exitNumricexprLong?: (ctx: NumricexprLongContext) => void;
	/**
	 * Enter a parse tree produced by the `strPlus`
	 * labeled alternative in `SmartRuleParser.stringexpr`.
	 * @param ctx the parse tree
	 */
	enterStrPlus?: (ctx: StrPlusContext) => void;
	/**
	 * Exit a parse tree produced by the `strPlus`
	 * labeled alternative in `SmartRuleParser.stringexpr`.
	 * @param ctx the parse tree
	 */
	exitStrPlus?: (ctx: StrPlusContext) => void;
	/**
	 * Enter a parse tree produced by the `strOrdString`
	 * labeled alternative in `SmartRuleParser.stringexpr`.
	 * @param ctx the parse tree
	 */
	enterStrOrdString?: (ctx: StrOrdStringContext) => void;
	/**
	 * Exit a parse tree produced by the `strOrdString`
	 * labeled alternative in `SmartRuleParser.stringexpr`.
	 * @param ctx the parse tree
	 */
	exitStrOrdString?: (ctx: StrOrdStringContext) => void;
	/**
	 * Enter a parse tree produced by the `strID`
	 * labeled alternative in `SmartRuleParser.stringexpr`.
	 * @param ctx the parse tree
	 */
	enterStrID?: (ctx: StrIDContext) => void;
	/**
	 * Exit a parse tree produced by the `strID`
	 * labeled alternative in `SmartRuleParser.stringexpr`.
	 * @param ctx the parse tree
	 */
	exitStrID?: (ctx: StrIDContext) => void;
	/**
	 * Enter a parse tree produced by the `strCurve`
	 * labeled alternative in `SmartRuleParser.stringexpr`.
	 * @param ctx the parse tree
	 */
	enterStrCurve?: (ctx: StrCurveContext) => void;
	/**
	 * Exit a parse tree produced by the `strCurve`
	 * labeled alternative in `SmartRuleParser.stringexpr`.
	 * @param ctx the parse tree
	 */
	exitStrCurve?: (ctx: StrCurveContext) => void;
	/**
	 * Enter a parse tree produced by the `strTimePointStr`
	 * labeled alternative in `SmartRuleParser.stringexpr`.
	 * @param ctx the parse tree
	 */
	enterStrTimePointStr?: (ctx: StrTimePointStrContext) => void;
	/**
	 * Exit a parse tree produced by the `strTimePointStr`
	 * labeled alternative in `SmartRuleParser.stringexpr`.
	 * @param ctx the parse tree
	 */
	exitStrTimePointStr?: (ctx: StrTimePointStrContext) => void;
	/**
	 * Enter a parse tree produced by `SmartRuleParser.cmdlet`.
	 * @param ctx the parse tree
	 */
	enterCmdlet?: (ctx: CmdletContext) => void;
	/**
	 * Exit a parse tree produced by `SmartRuleParser.cmdlet`.
	 * @param ctx the parse tree
	 */
	exitCmdlet?: (ctx: CmdletContext) => void;
	/**
	 * Enter a parse tree produced by the `idAtt`
	 * labeled alternative in `SmartRuleParser.id`.
	 * @param ctx the parse tree
	 */
	enterIdAtt?: (ctx: IdAttContext) => void;
	/**
	 * Exit a parse tree produced by the `idAtt`
	 * labeled alternative in `SmartRuleParser.id`.
	 * @param ctx the parse tree
	 */
	exitIdAtt?: (ctx: IdAttContext) => void;
	/**
	 * Enter a parse tree produced by the `idObjAtt`
	 * labeled alternative in `SmartRuleParser.id`.
	 * @param ctx the parse tree
	 */
	enterIdObjAtt?: (ctx: IdObjAttContext) => void;
	/**
	 * Exit a parse tree produced by the `idObjAtt`
	 * labeled alternative in `SmartRuleParser.id`.
	 * @param ctx the parse tree
	 */
	exitIdObjAtt?: (ctx: IdObjAttContext) => void;
	/**
	 * Enter a parse tree produced by the `idAttPara`
	 * labeled alternative in `SmartRuleParser.id`.
	 * @param ctx the parse tree
	 */
	enterIdAttPara?: (ctx: IdAttParaContext) => void;
	/**
	 * Exit a parse tree produced by the `idAttPara`
	 * labeled alternative in `SmartRuleParser.id`.
	 * @param ctx the parse tree
	 */
	exitIdAttPara?: (ctx: IdAttParaContext) => void;
	/**
	 * Enter a parse tree produced by the `idObjAttPara`
	 * labeled alternative in `SmartRuleParser.id`.
	 * @param ctx the parse tree
	 */
	enterIdObjAttPara?: (ctx: IdObjAttParaContext) => void;
	/**
	 * Exit a parse tree produced by the `idObjAttPara`
	 * labeled alternative in `SmartRuleParser.id`.
	 * @param ctx the parse tree
	 */
	exitIdObjAttPara?: (ctx: IdObjAttParaContext) => void;
	/**
	 * Enter a parse tree produced by `SmartRuleParser.opr`.
	 * @param ctx the parse tree
	 */
	enterOpr?: (ctx: OprContext) => void;
	/**
	 * Exit a parse tree produced by `SmartRuleParser.opr`.
	 * @param ctx the parse tree
	 */
	exitOpr?: (ctx: OprContext) => void;
	/**
	 * Enter a parse tree produced by `SmartRuleParser.fileEvent`.
	 * @param ctx the parse tree
	 */
	enterFileEvent?: (ctx: FileEventContext) => void;
	/**
	 * Exit a parse tree produced by `SmartRuleParser.fileEvent`.
	 * @param ctx the parse tree
	 */
	exitFileEvent?: (ctx: FileEventContext) => void;
	/**
	 * Enter a parse tree produced by the `constLong`
	 * labeled alternative in `SmartRuleParser.constexpr`.
	 * @param ctx the parse tree
	 */
	enterConstLong?: (ctx: ConstLongContext) => void;
	/**
	 * Exit a parse tree produced by the `constLong`
	 * labeled alternative in `SmartRuleParser.constexpr`.
	 * @param ctx the parse tree
	 */
	exitConstLong?: (ctx: ConstLongContext) => void;
	/**
	 * Enter a parse tree produced by the `constString`
	 * labeled alternative in `SmartRuleParser.constexpr`.
	 * @param ctx the parse tree
	 */
	enterConstString?: (ctx: ConstStringContext) => void;
	/**
	 * Exit a parse tree produced by the `constString`
	 * labeled alternative in `SmartRuleParser.constexpr`.
	 * @param ctx the parse tree
	 */
	exitConstString?: (ctx: ConstStringContext) => void;
	/**
	 * Enter a parse tree produced by the `constTimeInverval`
	 * labeled alternative in `SmartRuleParser.constexpr`.
	 * @param ctx the parse tree
	 */
	enterConstTimeInverval?: (ctx: ConstTimeInvervalContext) => void;
	/**
	 * Exit a parse tree produced by the `constTimeInverval`
	 * labeled alternative in `SmartRuleParser.constexpr`.
	 * @param ctx the parse tree
	 */
	exitConstTimeInverval?: (ctx: ConstTimeInvervalContext) => void;
	/**
	 * Enter a parse tree produced by the `constTimePoint`
	 * labeled alternative in `SmartRuleParser.constexpr`.
	 * @param ctx the parse tree
	 */
	enterConstTimePoint?: (ctx: ConstTimePointContext) => void;
	/**
	 * Exit a parse tree produced by the `constTimePoint`
	 * labeled alternative in `SmartRuleParser.constexpr`.
	 * @param ctx the parse tree
	 */
	exitConstTimePoint?: (ctx: ConstTimePointContext) => void;
}

