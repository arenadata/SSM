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
// noinspection ES6UnusedImports,JSUnusedGlobalSymbols,JSUnusedLocalSymbols

import {
	ATN,
	ATNDeserializer, DecisionState, DFA, FailedPredicateException,
	RecognitionException, NoViableAltException, BailErrorStrategy,
	Parser, ParserATNSimulator,
	RuleContext, ParserRuleContext, PredictionMode, PredictionContextCache,
	TerminalNode, RuleNode,
	Token, TokenStream,
	Interval, IntervalSet
} from 'antlr4';
import SmartRuleListener from "./SmartRuleListener.js";
// for running tests with parameters, TODO: discuss strategy for typed parameters in CI
// eslint-disable-next-line no-unused-vars
type int = number;

export default class SmartRuleParser extends Parser {
	public static readonly T__0 = 1;
	public static readonly T__1 = 2;
	public static readonly T__2 = 3;
	public static readonly T__3 = 4;
	public static readonly T__4 = 5;
	public static readonly T__5 = 6;
	public static readonly T__6 = 7;
	public static readonly T__7 = 8;
	public static readonly T__8 = 9;
	public static readonly T__9 = 10;
	public static readonly T__10 = 11;
	public static readonly T__11 = 12;
	public static readonly T__12 = 13;
	public static readonly T__13 = 14;
	public static readonly T__14 = 15;
	public static readonly T__15 = 16;
	public static readonly T__16 = 17;
	public static readonly T__17 = 18;
	public static readonly T__18 = 19;
	public static readonly T__19 = 20;
	public static readonly T__20 = 21;
	public static readonly T__21 = 22;
	public static readonly OPEQCMP = 23;
	public static readonly OPCMP = 24;
	public static readonly OBJECTTYPE = 25;
	public static readonly AT = 26;
	public static readonly AND = 27;
	public static readonly EVERY = 28;
	public static readonly FROM = 29;
	public static readonly ON = 30;
	public static readonly ONCE = 31;
	public static readonly OR = 32;
	public static readonly NOW = 33;
	public static readonly NOT = 34;
	public static readonly TO = 35;
	public static readonly WITH = 36;
	public static readonly MATCHES = 37;
	public static readonly FILECREATE = 38;
	public static readonly FILECLOSE = 39;
	public static readonly FILEAPPEND = 40;
	public static readonly FILERENAME = 41;
	public static readonly FILEMETADATA = 42;
	public static readonly FILEUNLINK = 43;
	public static readonly FILETRUNCATE = 44;
	public static readonly TIMEINTVALCONST = 45;
	public static readonly TIMEPOINTCONST = 46;
	public static readonly ID = 47;
	public static readonly Linecomment = 48;
	public static readonly WS = 49;
	public static readonly STRING = 50;
	public static readonly LONG = 51;
	public static readonly NEWLINE = 52;
	public static override readonly EOF = Token.EOF;
	public static readonly RULE_ssmrule = 0;
	public static readonly RULE_object = 1;
	public static readonly RULE_trigger = 2;
	public static readonly RULE_duringexpr = 3;
	public static readonly RULE_objfilter = 4;
	public static readonly RULE_conditions = 5;
	public static readonly RULE_boolvalue = 6;
	public static readonly RULE_compareexpr = 7;
	public static readonly RULE_timeintvalexpr = 8;
	public static readonly RULE_timepointexpr = 9;
	public static readonly RULE_commonexpr = 10;
	public static readonly RULE_numricexpr = 11;
	public static readonly RULE_stringexpr = 12;
	public static readonly RULE_cmdlet = 13;
	public static readonly RULE_id = 14;
	public static readonly RULE_opr = 15;
	public static readonly RULE_fileEvent = 16;
	public static readonly RULE_constexpr = 17;
	public static readonly literalNames: (string | null)[] = [ null, "':'", 
                                                            "'|'", "'/'", 
                                                            "'('", "')'", 
                                                            "'-'", "'+'", 
                                                            "'*'", "'%'", 
                                                            "';'", "'@'", 
                                                            "'$'", "'&'", 
                                                            "'='", "'{'", 
                                                            "'}'", "'['", 
                                                            "']'", "'\"'", 
                                                            "'?'", "'.'", 
                                                            "','", null, 
                                                            null, null, 
                                                            "'at'", "'and'", 
                                                            "'every'", "'from'", 
                                                            "'on'", "'once'", 
                                                            "'or'", "'now'", 
                                                            "'not'", "'to'", 
                                                            "'with'", "'matches'", 
                                                            "'FileCreate'", 
                                                            "'FileClose'", 
                                                            "'FileAppend'", 
                                                            "'FileRename'", 
                                                            "'FileMetadate'", 
                                                            "'FileUnlink'", 
                                                            "'FileTruncate'" ];
	public static readonly symbolicNames: (string | null)[] = [ null, null, 
                                                             null, null, 
                                                             null, null, 
                                                             null, null, 
                                                             null, null, 
                                                             null, null, 
                                                             null, null, 
                                                             null, null, 
                                                             null, null, 
                                                             null, null, 
                                                             null, null, 
                                                             null, "OPEQCMP", 
                                                             "OPCMP", "OBJECTTYPE", 
                                                             "AT", "AND", 
                                                             "EVERY", "FROM", 
                                                             "ON", "ONCE", 
                                                             "OR", "NOW", 
                                                             "NOT", "TO", 
                                                             "WITH", "MATCHES", 
                                                             "FILECREATE", 
                                                             "FILECLOSE", 
                                                             "FILEAPPEND", 
                                                             "FILERENAME", 
                                                             "FILEMETADATA", 
                                                             "FILEUNLINK", 
                                                             "FILETRUNCATE", 
                                                             "TIMEINTVALCONST", 
                                                             "TIMEPOINTCONST", 
                                                             "ID", "Linecomment", 
                                                             "WS", "STRING", 
                                                             "LONG", "NEWLINE" ];
	// tslint:disable:no-trailing-whitespace
	public static readonly ruleNames: string[] = [
		"ssmrule", "object", "trigger", "duringexpr", "objfilter", "conditions", 
		"boolvalue", "compareexpr", "timeintvalexpr", "timepointexpr", "commonexpr", 
		"numricexpr", "stringexpr", "cmdlet", "id", "opr", "fileEvent", "constexpr",
	];
	public get grammarFileName(): string { return "SmartRule.g4"; }
	public get literalNames(): (string | null)[] { return SmartRuleParser.literalNames; }
	public get symbolicNames(): (string | null)[] { return SmartRuleParser.symbolicNames; }
	public get ruleNames(): string[] { return SmartRuleParser.ruleNames; }
	public get serializedATN(): number[] { return SmartRuleParser._serializedATN; }

	protected createFailedPredicateException(predicate?: string, message?: string): FailedPredicateException {
		return new FailedPredicateException(this, predicate, message);
	}

	constructor(input: TokenStream) {
		super(input);
		this._interp = new ParserATNSimulator(this, SmartRuleParser._ATN, SmartRuleParser.DecisionsToDFA, new PredictionContextCache());
	}
	// @RuleVersion(0)
	public ssmrule(): SsmruleContext {
		let localctx: SsmruleContext = new SsmruleContext(this, this._ctx, this.state);
		this.enterRule(localctx, 0, SmartRuleParser.RULE_ssmrule);
		let _la: number;
		try {
			this.state = 52;
			this._errHandler.sync(this);
			switch (this._input.LA(1)) {
			case 25:
				localctx = new RuleLineContext(this, localctx);
				this.enterOuterAlt(localctx, 1);
				{
				this.state = 36;
				this.object();
				this.state = 37;
				this.match(SmartRuleParser.T__0);
				this.state = 41;
				this._errHandler.sync(this);
				_la = this._input.LA(1);
				if ((((_la) & ~0x1F) === 0 && ((1 << _la) & 3556769792) !== 0)) {
					{
					this.state = 38;
					this.trigger();
					this.state = 39;
					this.match(SmartRuleParser.T__1);
					}
				}

				this.state = 43;
				this.conditions();
				this.state = 44;
				this.match(SmartRuleParser.T__1);
				this.state = 45;
				this.cmdlet();
				}
				break;
			case 48:
				localctx = new CommentLineContext(this, localctx);
				this.enterOuterAlt(localctx, 2);
				{
				this.state = 48;
				this._errHandler.sync(this);
				_la = this._input.LA(1);
				do {
					{
					{
					this.state = 47;
					this.match(SmartRuleParser.Linecomment);
					}
					}
					this.state = 50;
					this._errHandler.sync(this);
					_la = this._input.LA(1);
				} while (_la===48);
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.exitRule();
		}
		return localctx;
	}
	// @RuleVersion(0)
	public object(): ObjectContext {
		let localctx: ObjectContext = new ObjectContext(this, this._ctx, this.state);
		this.enterRule(localctx, 2, SmartRuleParser.RULE_object);
		try {
			this.state = 58;
			this._errHandler.sync(this);
			switch ( this._interp.adaptivePredict(this._input, 3, this._ctx) ) {
			case 1:
				localctx = new ObjTypeOnlyContext(this, localctx);
				this.enterOuterAlt(localctx, 1);
				{
				this.state = 54;
				this.match(SmartRuleParser.OBJECTTYPE);
				}
				break;
			case 2:
				localctx = new ObjTypeWithContext(this, localctx);
				this.enterOuterAlt(localctx, 2);
				{
				this.state = 55;
				this.match(SmartRuleParser.OBJECTTYPE);
				this.state = 56;
				this.match(SmartRuleParser.WITH);
				this.state = 57;
				this.objfilter();
				}
				break;
			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.exitRule();
		}
		return localctx;
	}
	// @RuleVersion(0)
	public trigger(): TriggerContext {
		let localctx: TriggerContext = new TriggerContext(this, this._ctx, this.state);
		this.enterRule(localctx, 4, SmartRuleParser.RULE_trigger);
		let _la: number;
		try {
			this.state = 81;
			this._errHandler.sync(this);
			switch (this._input.LA(1)) {
			case 26:
				localctx = new TriTimePointContext(this, localctx);
				this.enterOuterAlt(localctx, 1);
				{
				this.state = 60;
				this.match(SmartRuleParser.AT);
				this.state = 61;
				this.timepointexpr(0);
				}
				break;
			case 28:
				localctx = new TriCycleContext(this, localctx);
				this.enterOuterAlt(localctx, 2);
				{
				this.state = 62;
				this.match(SmartRuleParser.EVERY);
				this.state = 63;
				this.timeintvalexpr(0);
				this.state = 70;
				this._errHandler.sync(this);
				_la = this._input.LA(1);
				if (_la===3) {
					{
					this.state = 64;
					this.match(SmartRuleParser.T__2);
					this.state = 65;
					this.timeintvalexpr(0);
					this.state = 68;
					this._errHandler.sync(this);
					_la = this._input.LA(1);
					if (_la===3) {
						{
						this.state = 66;
						this.match(SmartRuleParser.T__2);
						this.state = 67;
						this.timeintvalexpr(0);
						}
					}

					}
				}

				this.state = 73;
				this._errHandler.sync(this);
				_la = this._input.LA(1);
				if (_la===29) {
					{
					this.state = 72;
					this.duringexpr();
					}
				}

				}
				break;
			case 30:
				localctx = new TriFileEventContext(this, localctx);
				this.enterOuterAlt(localctx, 3);
				{
				this.state = 75;
				this.match(SmartRuleParser.ON);
				this.state = 76;
				this.fileEvent();
				this.state = 78;
				this._errHandler.sync(this);
				_la = this._input.LA(1);
				if (_la===29) {
					{
					this.state = 77;
					this.duringexpr();
					}
				}

				}
				break;
			case 31:
				localctx = new TriOnceContext(this, localctx);
				this.enterOuterAlt(localctx, 4);
				{
				this.state = 80;
				this.match(SmartRuleParser.ONCE);
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.exitRule();
		}
		return localctx;
	}
	// @RuleVersion(0)
	public duringexpr(): DuringexprContext {
		let localctx: DuringexprContext = new DuringexprContext(this, this._ctx, this.state);
		this.enterRule(localctx, 6, SmartRuleParser.RULE_duringexpr);
		let _la: number;
		try {
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 83;
			this.match(SmartRuleParser.FROM);
			this.state = 84;
			this.timepointexpr(0);
			this.state = 87;
			this._errHandler.sync(this);
			_la = this._input.LA(1);
			if (_la===35) {
				{
				this.state = 85;
				this.match(SmartRuleParser.TO);
				this.state = 86;
				this.timepointexpr(0);
				}
			}

			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.exitRule();
		}
		return localctx;
	}
	// @RuleVersion(0)
	public objfilter(): ObjfilterContext {
		let localctx: ObjfilterContext = new ObjfilterContext(this, this._ctx, this.state);
		this.enterRule(localctx, 8, SmartRuleParser.RULE_objfilter);
		try {
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 89;
			this.boolvalue(0);
			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.exitRule();
		}
		return localctx;
	}
	// @RuleVersion(0)
	public conditions(): ConditionsContext {
		let localctx: ConditionsContext = new ConditionsContext(this, this._ctx, this.state);
		this.enterRule(localctx, 10, SmartRuleParser.RULE_conditions);
		try {
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 91;
			this.boolvalue(0);
			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.exitRule();
		}
		return localctx;
	}

	public boolvalue(): BoolvalueContext;
	public boolvalue(_p: number): BoolvalueContext;
	// @RuleVersion(0)
	public boolvalue(_p?: number): BoolvalueContext {
		if (_p === undefined) {
			_p = 0;
		}

		let _parentctx: ParserRuleContext = this._ctx;
		let _parentState: number = this.state;
		let localctx: BoolvalueContext = new BoolvalueContext(this, this._ctx, _parentState);
		let _prevctx: BoolvalueContext = localctx;
		let _startState: number = 12;
		this.enterRecursionRule(localctx, 12, SmartRuleParser.RULE_boolvalue, _p);
		let _la: number;
		try {
			let _alt: number;
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 102;
			this._errHandler.sync(this);
			switch ( this._interp.adaptivePredict(this._input, 10, this._ctx) ) {
			case 1:
				{
				localctx = new BvCompareexprContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;

				this.state = 94;
				this.compareexpr();
				}
				break;
			case 2:
				{
				localctx = new BvNotContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 95;
				this.match(SmartRuleParser.NOT);
				this.state = 96;
				this.boolvalue(4);
				}
				break;
			case 3:
				{
				localctx = new BvIdContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 97;
				this.id();
				}
				break;
			case 4:
				{
				localctx = new BvCurveContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 98;
				this.match(SmartRuleParser.T__3);
				this.state = 99;
				this.boolvalue(0);
				this.state = 100;
				this.match(SmartRuleParser.T__4);
				}
				break;
			}
			this._ctx.stop = this._input.LT(-1);
			this.state = 109;
			this._errHandler.sync(this);
			_alt = this._interp.adaptivePredict(this._input, 11, this._ctx);
			while (_alt !== 2 && _alt !== ATN.INVALID_ALT_NUMBER) {
				if (_alt === 1) {
					if (this._parseListeners != null) {
						this.triggerExitRuleEvent();
					}
					_prevctx = localctx;
					{
					{
					localctx = new BvAndORContext(this, new BoolvalueContext(this, _parentctx, _parentState));
					this.pushNewRecursionContext(localctx, _startState, SmartRuleParser.RULE_boolvalue);
					this.state = 104;
					if (!(this.precpred(this._ctx, 3))) {
						throw this.createFailedPredicateException("this.precpred(this._ctx, 3)");
					}
					this.state = 105;
					_la = this._input.LA(1);
					if(!(_la===27 || _la===32)) {
					this._errHandler.recoverInline(this);
					}
					else {
						this._errHandler.reportMatch(this);
					    this.consume();
					}
					this.state = 106;
					this.boolvalue(4);
					}
					}
				}
				this.state = 111;
				this._errHandler.sync(this);
				_alt = this._interp.adaptivePredict(this._input, 11, this._ctx);
			}
			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.unrollRecursionContexts(_parentctx);
		}
		return localctx;
	}
	// @RuleVersion(0)
	public compareexpr(): CompareexprContext {
		let localctx: CompareexprContext = new CompareexprContext(this, this._ctx, this.state);
		this.enterRule(localctx, 14, SmartRuleParser.RULE_compareexpr);
		try {
			this.state = 132;
			this._errHandler.sync(this);
			switch ( this._interp.adaptivePredict(this._input, 12, this._ctx) ) {
			case 1:
				localctx = new CmpIdLongContext(this, localctx);
				this.enterOuterAlt(localctx, 1);
				{
				this.state = 112;
				this.numricexpr(0);
				this.state = 113;
				this.match(SmartRuleParser.OPCMP);
				this.state = 114;
				this.numricexpr(0);
				}
				break;
			case 2:
				localctx = new CmpIdStringContext(this, localctx);
				this.enterOuterAlt(localctx, 2);
				{
				this.state = 116;
				this.stringexpr(0);
				this.state = 117;
				this.match(SmartRuleParser.OPEQCMP);
				this.state = 118;
				this.stringexpr(0);
				}
				break;
			case 3:
				localctx = new CmpIdStringMatchesContext(this, localctx);
				this.enterOuterAlt(localctx, 3);
				{
				this.state = 120;
				this.stringexpr(0);
				this.state = 121;
				this.match(SmartRuleParser.MATCHES);
				this.state = 122;
				this.stringexpr(0);
				}
				break;
			case 4:
				localctx = new CmpTimeintvalTimeintvalContext(this, localctx);
				this.enterOuterAlt(localctx, 4);
				{
				this.state = 124;
				this.timeintvalexpr(0);
				this.state = 125;
				this.match(SmartRuleParser.OPCMP);
				this.state = 126;
				this.timeintvalexpr(0);
				}
				break;
			case 5:
				localctx = new CmpTimepointTimePointContext(this, localctx);
				this.enterOuterAlt(localctx, 5);
				{
				this.state = 128;
				this.timepointexpr(0);
				this.state = 129;
				this.match(SmartRuleParser.OPCMP);
				this.state = 130;
				this.timepointexpr(0);
				}
				break;
			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.exitRule();
		}
		return localctx;
	}

	public timeintvalexpr(): TimeintvalexprContext;
	public timeintvalexpr(_p: number): TimeintvalexprContext;
	// @RuleVersion(0)
	public timeintvalexpr(_p?: number): TimeintvalexprContext {
		if (_p === undefined) {
			_p = 0;
		}

		let _parentctx: ParserRuleContext = this._ctx;
		let _parentState: number = this.state;
		let localctx: TimeintvalexprContext = new TimeintvalexprContext(this, this._ctx, _parentState);
		let _prevctx: TimeintvalexprContext = localctx;
		let _startState: number = 16;
		this.enterRecursionRule(localctx, 16, SmartRuleParser.RULE_timeintvalexpr, _p);
		let _la: number;
		try {
			let _alt: number;
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 145;
			this._errHandler.sync(this);
			switch ( this._interp.adaptivePredict(this._input, 13, this._ctx) ) {
			case 1:
				{
				localctx = new TieCurvesContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;

				this.state = 135;
				this.match(SmartRuleParser.T__3);
				this.state = 136;
				this.timeintvalexpr(0);
				this.state = 137;
				this.match(SmartRuleParser.T__4);
				}
				break;
			case 2:
				{
				localctx = new TieConstContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 139;
				this.match(SmartRuleParser.TIMEINTVALCONST);
				}
				break;
			case 3:
				{
				localctx = new TieTpExprContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 140;
				this.timepointexpr(0);
				this.state = 141;
				this.match(SmartRuleParser.T__5);
				this.state = 142;
				this.timepointexpr(0);
				}
				break;
			case 4:
				{
				localctx = new TieTiIdExprContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 144;
				this.id();
				}
				break;
			}
			this._ctx.stop = this._input.LT(-1);
			this.state = 152;
			this._errHandler.sync(this);
			_alt = this._interp.adaptivePredict(this._input, 14, this._ctx);
			while (_alt !== 2 && _alt !== ATN.INVALID_ALT_NUMBER) {
				if (_alt === 1) {
					if (this._parseListeners != null) {
						this.triggerExitRuleEvent();
					}
					_prevctx = localctx;
					{
					{
					localctx = new TieTiExprContext(this, new TimeintvalexprContext(this, _parentctx, _parentState));
					this.pushNewRecursionContext(localctx, _startState, SmartRuleParser.RULE_timeintvalexpr);
					this.state = 147;
					if (!(this.precpred(this._ctx, 2))) {
						throw this.createFailedPredicateException("this.precpred(this._ctx, 2)");
					}
					this.state = 148;
					_la = this._input.LA(1);
					if(!(_la===6 || _la===7)) {
					this._errHandler.recoverInline(this);
					}
					else {
						this._errHandler.reportMatch(this);
					    this.consume();
					}
					this.state = 149;
					this.timeintvalexpr(3);
					}
					}
				}
				this.state = 154;
				this._errHandler.sync(this);
				_alt = this._interp.adaptivePredict(this._input, 14, this._ctx);
			}
			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.unrollRecursionContexts(_parentctx);
		}
		return localctx;
	}

	public timepointexpr(): TimepointexprContext;
	public timepointexpr(_p: number): TimepointexprContext;
	// @RuleVersion(0)
	public timepointexpr(_p?: number): TimepointexprContext {
		if (_p === undefined) {
			_p = 0;
		}

		let _parentctx: ParserRuleContext = this._ctx;
		let _parentState: number = this.state;
		let localctx: TimepointexprContext = new TimepointexprContext(this, this._ctx, _parentState);
		let _prevctx: TimepointexprContext = localctx;
		let _startState: number = 18;
		this.enterRecursionRule(localctx, 18, SmartRuleParser.RULE_timepointexpr, _p);
		let _la: number;
		try {
			let _alt: number;
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 163;
			this._errHandler.sync(this);
			switch (this._input.LA(1)) {
			case 4:
				{
				localctx = new TpeCurvesContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;

				this.state = 156;
				this.match(SmartRuleParser.T__3);
				this.state = 157;
				this.timepointexpr(0);
				this.state = 158;
				this.match(SmartRuleParser.T__4);
				}
				break;
			case 33:
				{
				localctx = new TpeNowContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 160;
				this.match(SmartRuleParser.NOW);
				}
				break;
			case 46:
				{
				localctx = new TpeTimeConstContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 161;
				this.match(SmartRuleParser.TIMEPOINTCONST);
				}
				break;
			case 25:
			case 47:
				{
				localctx = new TpeTimeIdContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 162;
				this.id();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
			this._ctx.stop = this._input.LT(-1);
			this.state = 170;
			this._errHandler.sync(this);
			_alt = this._interp.adaptivePredict(this._input, 16, this._ctx);
			while (_alt !== 2 && _alt !== ATN.INVALID_ALT_NUMBER) {
				if (_alt === 1) {
					if (this._parseListeners != null) {
						this.triggerExitRuleEvent();
					}
					_prevctx = localctx;
					{
					{
					localctx = new TpeTimeExprContext(this, new TimepointexprContext(this, _parentctx, _parentState));
					this.pushNewRecursionContext(localctx, _startState, SmartRuleParser.RULE_timepointexpr);
					this.state = 165;
					if (!(this.precpred(this._ctx, 2))) {
						throw this.createFailedPredicateException("this.precpred(this._ctx, 2)");
					}
					this.state = 166;
					_la = this._input.LA(1);
					if(!(_la===6 || _la===7)) {
					this._errHandler.recoverInline(this);
					}
					else {
						this._errHandler.reportMatch(this);
					    this.consume();
					}
					this.state = 167;
					this.timeintvalexpr(0);
					}
					}
				}
				this.state = 172;
				this._errHandler.sync(this);
				_alt = this._interp.adaptivePredict(this._input, 16, this._ctx);
			}
			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.unrollRecursionContexts(_parentctx);
		}
		return localctx;
	}
	// @RuleVersion(0)
	public commonexpr(): CommonexprContext {
		let localctx: CommonexprContext = new CommonexprContext(this, this._ctx, this.state);
		this.enterRule(localctx, 20, SmartRuleParser.RULE_commonexpr);
		try {
			this.state = 184;
			this._errHandler.sync(this);
			switch ( this._interp.adaptivePredict(this._input, 17, this._ctx) ) {
			case 1:
				this.enterOuterAlt(localctx, 1);
				{
				this.state = 173;
				this.boolvalue(0);
				}
				break;
			case 2:
				this.enterOuterAlt(localctx, 2);
				{
				this.state = 174;
				this.timeintvalexpr(0);
				}
				break;
			case 3:
				this.enterOuterAlt(localctx, 3);
				{
				this.state = 175;
				this.timepointexpr(0);
				}
				break;
			case 4:
				this.enterOuterAlt(localctx, 4);
				{
				this.state = 176;
				this.numricexpr(0);
				}
				break;
			case 5:
				this.enterOuterAlt(localctx, 5);
				{
				this.state = 177;
				this.match(SmartRuleParser.LONG);
				}
				break;
			case 6:
				this.enterOuterAlt(localctx, 6);
				{
				this.state = 178;
				this.match(SmartRuleParser.STRING);
				}
				break;
			case 7:
				this.enterOuterAlt(localctx, 7);
				{
				this.state = 179;
				this.id();
				}
				break;
			case 8:
				this.enterOuterAlt(localctx, 8);
				{
				this.state = 180;
				this.match(SmartRuleParser.T__3);
				this.state = 181;
				this.commonexpr();
				this.state = 182;
				this.match(SmartRuleParser.T__4);
				}
				break;
			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.exitRule();
		}
		return localctx;
	}

	public numricexpr(): NumricexprContext;
	public numricexpr(_p: number): NumricexprContext;
	// @RuleVersion(0)
	public numricexpr(_p?: number): NumricexprContext {
		if (_p === undefined) {
			_p = 0;
		}

		let _parentctx: ParserRuleContext = this._ctx;
		let _parentState: number = this.state;
		let localctx: NumricexprContext = new NumricexprContext(this, this._ctx, _parentState);
		let _prevctx: NumricexprContext = localctx;
		let _startState: number = 22;
		this.enterRecursionRule(localctx, 22, SmartRuleParser.RULE_numricexpr, _p);
		let _la: number;
		try {
			let _alt: number;
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 193;
			this._errHandler.sync(this);
			switch (this._input.LA(1)) {
			case 25:
			case 47:
				{
				localctx = new NumricexprIdContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;

				this.state = 187;
				this.id();
				}
				break;
			case 51:
				{
				localctx = new NumricexprLongContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 188;
				this.match(SmartRuleParser.LONG);
				}
				break;
			case 4:
				{
				localctx = new NumricexprCurveContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 189;
				this.match(SmartRuleParser.T__3);
				this.state = 190;
				this.numricexpr(0);
				this.state = 191;
				this.match(SmartRuleParser.T__4);
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
			this._ctx.stop = this._input.LT(-1);
			this.state = 203;
			this._errHandler.sync(this);
			_alt = this._interp.adaptivePredict(this._input, 20, this._ctx);
			while (_alt !== 2 && _alt !== ATN.INVALID_ALT_NUMBER) {
				if (_alt === 1) {
					if (this._parseListeners != null) {
						this.triggerExitRuleEvent();
					}
					_prevctx = localctx;
					{
					this.state = 201;
					this._errHandler.sync(this);
					switch ( this._interp.adaptivePredict(this._input, 19, this._ctx) ) {
					case 1:
						{
						localctx = new NumricexprMulContext(this, new NumricexprContext(this, _parentctx, _parentState));
						this.pushNewRecursionContext(localctx, _startState, SmartRuleParser.RULE_numricexpr);
						this.state = 195;
						if (!(this.precpred(this._ctx, 5))) {
							throw this.createFailedPredicateException("this.precpred(this._ctx, 5)");
						}
						this.state = 196;
						(localctx as NumricexprMulContext)._op = this._input.LT(1);
						_la = this._input.LA(1);
						if(!((((_la) & ~0x1F) === 0 && ((1 << _la) & 776) !== 0))) {
						    (localctx as NumricexprMulContext)._op = this._errHandler.recoverInline(this);
						}
						else {
							this._errHandler.reportMatch(this);
						    this.consume();
						}
						this.state = 197;
						this.numricexpr(6);
						}
						break;
					case 2:
						{
						localctx = new NumricexprAddContext(this, new NumricexprContext(this, _parentctx, _parentState));
						this.pushNewRecursionContext(localctx, _startState, SmartRuleParser.RULE_numricexpr);
						this.state = 198;
						if (!(this.precpred(this._ctx, 4))) {
							throw this.createFailedPredicateException("this.precpred(this._ctx, 4)");
						}
						this.state = 199;
						(localctx as NumricexprAddContext)._op = this._input.LT(1);
						_la = this._input.LA(1);
						if(!(_la===6 || _la===7)) {
						    (localctx as NumricexprAddContext)._op = this._errHandler.recoverInline(this);
						}
						else {
							this._errHandler.reportMatch(this);
						    this.consume();
						}
						this.state = 200;
						this.numricexpr(5);
						}
						break;
					}
					}
				}
				this.state = 205;
				this._errHandler.sync(this);
				_alt = this._interp.adaptivePredict(this._input, 20, this._ctx);
			}
			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.unrollRecursionContexts(_parentctx);
		}
		return localctx;
	}

	public stringexpr(): StringexprContext;
	public stringexpr(_p: number): StringexprContext;
	// @RuleVersion(0)
	public stringexpr(_p?: number): StringexprContext {
		if (_p === undefined) {
			_p = 0;
		}

		let _parentctx: ParserRuleContext = this._ctx;
		let _parentState: number = this.state;
		let localctx: StringexprContext = new StringexprContext(this, this._ctx, _parentState);
		let _prevctx: StringexprContext = localctx;
		let _startState: number = 24;
		this.enterRecursionRule(localctx, 24, SmartRuleParser.RULE_stringexpr, _p);
		try {
			let _alt: number;
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 214;
			this._errHandler.sync(this);
			switch (this._input.LA(1)) {
			case 4:
				{
				localctx = new StrCurveContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;

				this.state = 207;
				this.match(SmartRuleParser.T__3);
				this.state = 208;
				this.stringexpr(0);
				this.state = 209;
				this.match(SmartRuleParser.T__4);
				}
				break;
			case 50:
				{
				localctx = new StrOrdStringContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 211;
				this.match(SmartRuleParser.STRING);
				}
				break;
			case 46:
				{
				localctx = new StrTimePointStrContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 212;
				this.match(SmartRuleParser.TIMEPOINTCONST);
				}
				break;
			case 25:
			case 47:
				{
				localctx = new StrIDContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 213;
				this.id();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
			this._ctx.stop = this._input.LT(-1);
			this.state = 221;
			this._errHandler.sync(this);
			_alt = this._interp.adaptivePredict(this._input, 22, this._ctx);
			while (_alt !== 2 && _alt !== ATN.INVALID_ALT_NUMBER) {
				if (_alt === 1) {
					if (this._parseListeners != null) {
						this.triggerExitRuleEvent();
					}
					_prevctx = localctx;
					{
					{
					localctx = new StrPlusContext(this, new StringexprContext(this, _parentctx, _parentState));
					this.pushNewRecursionContext(localctx, _startState, SmartRuleParser.RULE_stringexpr);
					this.state = 216;
					if (!(this.precpred(this._ctx, 1))) {
						throw this.createFailedPredicateException("this.precpred(this._ctx, 1)");
					}
					this.state = 217;
					this.match(SmartRuleParser.T__6);
					this.state = 218;
					this.stringexpr(2);
					}
					}
				}
				this.state = 223;
				this._errHandler.sync(this);
				_alt = this._interp.adaptivePredict(this._input, 22, this._ctx);
			}
			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.unrollRecursionContexts(_parentctx);
		}
		return localctx;
	}
	// @RuleVersion(0)
	public cmdlet(): CmdletContext {
		let localctx: CmdletContext = new CmdletContext(this, this._ctx, this.state);
		this.enterRule(localctx, 26, SmartRuleParser.RULE_cmdlet);
		let _la: number;
		try {
			this.state = 241;
			this._errHandler.sync(this);
			switch ( this._interp.adaptivePredict(this._input, 24, this._ctx) ) {
			case 1:
				this.enterOuterAlt(localctx, 1);
				{
				this.state = 227;
				this._errHandler.sync(this);
				_la = this._input.LA(1);
				while ((((_la) & ~0x1F) === 0 && ((1 << _la) & 4294967294) !== 0) || ((((_la - 32)) & ~0x1F) === 0 && ((1 << (_la - 32)) & 2097151) !== 0)) {
					{
					{
					this.state = 224;
					this.matchWildcard();
					}
					}
					this.state = 229;
					this._errHandler.sync(this);
					_la = this._input.LA(1);
				}
				}
				break;
			case 2:
				this.enterOuterAlt(localctx, 2);
				{
				this.state = 230;
				this.match(SmartRuleParser.T__9);
				}
				break;
			case 3:
				this.enterOuterAlt(localctx, 3);
				{
				this.state = 231;
				this.match(SmartRuleParser.T__10);
				}
				break;
			case 4:
				this.enterOuterAlt(localctx, 4);
				{
				this.state = 232;
				this.match(SmartRuleParser.T__11);
				}
				break;
			case 5:
				this.enterOuterAlt(localctx, 5);
				{
				this.state = 233;
				this.match(SmartRuleParser.T__12);
				}
				break;
			case 6:
				this.enterOuterAlt(localctx, 6);
				{
				this.state = 234;
				this.match(SmartRuleParser.T__13);
				}
				break;
			case 7:
				this.enterOuterAlt(localctx, 7);
				{
				this.state = 235;
				this.match(SmartRuleParser.T__14);
				}
				break;
			case 8:
				this.enterOuterAlt(localctx, 8);
				{
				this.state = 236;
				this.match(SmartRuleParser.T__15);
				}
				break;
			case 9:
				this.enterOuterAlt(localctx, 9);
				{
				this.state = 237;
				this.match(SmartRuleParser.T__16);
				}
				break;
			case 10:
				this.enterOuterAlt(localctx, 10);
				{
				this.state = 238;
				this.match(SmartRuleParser.T__17);
				}
				break;
			case 11:
				this.enterOuterAlt(localctx, 11);
				{
				this.state = 239;
				this.match(SmartRuleParser.T__18);
				}
				break;
			case 12:
				this.enterOuterAlt(localctx, 12);
				{
				this.state = 240;
				this.match(SmartRuleParser.T__19);
				}
				break;
			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.exitRule();
		}
		return localctx;
	}
	// @RuleVersion(0)
	public id(): IdContext {
		let localctx: IdContext = new IdContext(this, this._ctx, this.state);
		this.enterRule(localctx, 28, SmartRuleParser.RULE_id);
		let _la: number;
		try {
			this.state = 273;
			this._errHandler.sync(this);
			switch ( this._interp.adaptivePredict(this._input, 27, this._ctx) ) {
			case 1:
				localctx = new IdAttContext(this, localctx);
				this.enterOuterAlt(localctx, 1);
				{
				this.state = 243;
				this.match(SmartRuleParser.ID);
				}
				break;
			case 2:
				localctx = new IdObjAttContext(this, localctx);
				this.enterOuterAlt(localctx, 2);
				{
				this.state = 244;
				this.match(SmartRuleParser.OBJECTTYPE);
				this.state = 245;
				this.match(SmartRuleParser.T__20);
				this.state = 246;
				this.match(SmartRuleParser.ID);
				}
				break;
			case 3:
				localctx = new IdAttParaContext(this, localctx);
				this.enterOuterAlt(localctx, 3);
				{
				this.state = 247;
				this.match(SmartRuleParser.ID);
				this.state = 248;
				this.match(SmartRuleParser.T__3);
				this.state = 249;
				this.constexpr();
				this.state = 254;
				this._errHandler.sync(this);
				_la = this._input.LA(1);
				while (_la===22) {
					{
					{
					this.state = 250;
					this.match(SmartRuleParser.T__21);
					this.state = 251;
					this.constexpr();
					}
					}
					this.state = 256;
					this._errHandler.sync(this);
					_la = this._input.LA(1);
				}
				this.state = 257;
				this.match(SmartRuleParser.T__4);
				}
				break;
			case 4:
				localctx = new IdObjAttParaContext(this, localctx);
				this.enterOuterAlt(localctx, 4);
				{
				this.state = 259;
				this.match(SmartRuleParser.OBJECTTYPE);
				this.state = 260;
				this.match(SmartRuleParser.T__20);
				this.state = 261;
				this.match(SmartRuleParser.ID);
				this.state = 262;
				this.match(SmartRuleParser.T__3);
				this.state = 263;
				this.constexpr();
				this.state = 268;
				this._errHandler.sync(this);
				_la = this._input.LA(1);
				while (_la===22) {
					{
					{
					this.state = 264;
					this.match(SmartRuleParser.T__21);
					this.state = 265;
					this.constexpr();
					}
					}
					this.state = 270;
					this._errHandler.sync(this);
					_la = this._input.LA(1);
				}
				this.state = 271;
				this.match(SmartRuleParser.T__4);
				}
				break;
			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.exitRule();
		}
		return localctx;
	}
	// @RuleVersion(0)
	public opr(): OprContext {
		let localctx: OprContext = new OprContext(this, this._ctx, this.state);
		this.enterRule(localctx, 30, SmartRuleParser.RULE_opr);
		let _la: number;
		try {
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 275;
			_la = this._input.LA(1);
			if(!((((_la) & ~0x1F) === 0 && ((1 << _la) & 968) !== 0))) {
			this._errHandler.recoverInline(this);
			}
			else {
				this._errHandler.reportMatch(this);
			    this.consume();
			}
			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.exitRule();
		}
		return localctx;
	}
	// @RuleVersion(0)
	public fileEvent(): FileEventContext {
		let localctx: FileEventContext = new FileEventContext(this, this._ctx, this.state);
		this.enterRule(localctx, 32, SmartRuleParser.RULE_fileEvent);
		let _la: number;
		try {
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 277;
			_la = this._input.LA(1);
			if(!(((((_la - 38)) & ~0x1F) === 0 && ((1 << (_la - 38)) & 127) !== 0))) {
			this._errHandler.recoverInline(this);
			}
			else {
				this._errHandler.reportMatch(this);
			    this.consume();
			}
			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.exitRule();
		}
		return localctx;
	}
	// @RuleVersion(0)
	public constexpr(): ConstexprContext {
		let localctx: ConstexprContext = new ConstexprContext(this, this._ctx, this.state);
		this.enterRule(localctx, 34, SmartRuleParser.RULE_constexpr);
		try {
			this.state = 283;
			this._errHandler.sync(this);
			switch (this._input.LA(1)) {
			case 51:
				localctx = new ConstLongContext(this, localctx);
				this.enterOuterAlt(localctx, 1);
				{
				this.state = 279;
				this.match(SmartRuleParser.LONG);
				}
				break;
			case 50:
				localctx = new ConstStringContext(this, localctx);
				this.enterOuterAlt(localctx, 2);
				{
				this.state = 280;
				this.match(SmartRuleParser.STRING);
				}
				break;
			case 45:
				localctx = new ConstTimeInvervalContext(this, localctx);
				this.enterOuterAlt(localctx, 3);
				{
				this.state = 281;
				this.match(SmartRuleParser.TIMEINTVALCONST);
				}
				break;
			case 46:
				localctx = new ConstTimePointContext(this, localctx);
				this.enterOuterAlt(localctx, 4);
				{
				this.state = 282;
				this.match(SmartRuleParser.TIMEPOINTCONST);
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
		}
		catch (re) {
			if (re instanceof RecognitionException) {
				localctx.exception = re;
				this._errHandler.reportError(this, re);
				this._errHandler.recover(this, re);
			} else {
				throw re;
			}
		}
		finally {
			this.exitRule();
		}
		return localctx;
	}

	public sempred(localctx: RuleContext, ruleIndex: number, predIndex: number): boolean {
		switch (ruleIndex) {
		case 6:
			return this.boolvalue_sempred(localctx as BoolvalueContext, predIndex);
		case 8:
			return this.timeintvalexpr_sempred(localctx as TimeintvalexprContext, predIndex);
		case 9:
			return this.timepointexpr_sempred(localctx as TimepointexprContext, predIndex);
		case 11:
			return this.numricexpr_sempred(localctx as NumricexprContext, predIndex);
		case 12:
			return this.stringexpr_sempred(localctx as StringexprContext, predIndex);
		}
		return true;
	}
	private boolvalue_sempred(localctx: BoolvalueContext, predIndex: number): boolean {
		switch (predIndex) {
		case 0:
			return this.precpred(this._ctx, 3);
		}
		return true;
	}
	private timeintvalexpr_sempred(localctx: TimeintvalexprContext, predIndex: number): boolean {
		switch (predIndex) {
		case 1:
			return this.precpred(this._ctx, 2);
		}
		return true;
	}
	private timepointexpr_sempred(localctx: TimepointexprContext, predIndex: number): boolean {
		switch (predIndex) {
		case 2:
			return this.precpred(this._ctx, 2);
		}
		return true;
	}
	private numricexpr_sempred(localctx: NumricexprContext, predIndex: number): boolean {
		switch (predIndex) {
		case 3:
			return this.precpred(this._ctx, 5);
		case 4:
			return this.precpred(this._ctx, 4);
		}
		return true;
	}
	private stringexpr_sempred(localctx: StringexprContext, predIndex: number): boolean {
		switch (predIndex) {
		case 5:
			return this.precpred(this._ctx, 1);
		}
		return true;
	}

	public static readonly _serializedATN: number[] = [4,1,52,286,2,0,7,0,2,
	1,7,1,2,2,7,2,2,3,7,3,2,4,7,4,2,5,7,5,2,6,7,6,2,7,7,7,2,8,7,8,2,9,7,9,2,
	10,7,10,2,11,7,11,2,12,7,12,2,13,7,13,2,14,7,14,2,15,7,15,2,16,7,16,2,17,
	7,17,1,0,1,0,1,0,1,0,1,0,3,0,42,8,0,1,0,1,0,1,0,1,0,1,0,4,0,49,8,0,11,0,
	12,0,50,3,0,53,8,0,1,1,1,1,1,1,1,1,3,1,59,8,1,1,2,1,2,1,2,1,2,1,2,1,2,1,
	2,1,2,3,2,69,8,2,3,2,71,8,2,1,2,3,2,74,8,2,1,2,1,2,1,2,3,2,79,8,2,1,2,3,
	2,82,8,2,1,3,1,3,1,3,1,3,3,3,88,8,3,1,4,1,4,1,5,1,5,1,6,1,6,1,6,1,6,1,6,
	1,6,1,6,1,6,1,6,3,6,103,8,6,1,6,1,6,1,6,5,6,108,8,6,10,6,12,6,111,9,6,1,
	7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,
	7,1,7,3,7,133,8,7,1,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,3,8,146,8,
	8,1,8,1,8,1,8,5,8,151,8,8,10,8,12,8,154,9,8,1,9,1,9,1,9,1,9,1,9,1,9,1,9,
	1,9,3,9,164,8,9,1,9,1,9,1,9,5,9,169,8,9,10,9,12,9,172,9,9,1,10,1,10,1,10,
	1,10,1,10,1,10,1,10,1,10,1,10,1,10,1,10,3,10,185,8,10,1,11,1,11,1,11,1,
	11,1,11,1,11,1,11,3,11,194,8,11,1,11,1,11,1,11,1,11,1,11,1,11,5,11,202,
	8,11,10,11,12,11,205,9,11,1,12,1,12,1,12,1,12,1,12,1,12,1,12,1,12,3,12,
	215,8,12,1,12,1,12,1,12,5,12,220,8,12,10,12,12,12,223,9,12,1,13,5,13,226,
	8,13,10,13,12,13,229,9,13,1,13,1,13,1,13,1,13,1,13,1,13,1,13,1,13,1,13,
	1,13,1,13,3,13,242,8,13,1,14,1,14,1,14,1,14,1,14,1,14,1,14,1,14,1,14,5,
	14,253,8,14,10,14,12,14,256,9,14,1,14,1,14,1,14,1,14,1,14,1,14,1,14,1,14,
	1,14,5,14,267,8,14,10,14,12,14,270,9,14,1,14,1,14,3,14,274,8,14,1,15,1,
	15,1,16,1,16,1,17,1,17,1,17,1,17,3,17,284,8,17,1,17,0,5,12,16,18,22,24,
	18,0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,0,5,2,0,27,27,32,32,
	1,0,6,7,2,0,3,3,8,9,2,0,3,3,6,9,1,0,38,44,330,0,52,1,0,0,0,2,58,1,0,0,0,
	4,81,1,0,0,0,6,83,1,0,0,0,8,89,1,0,0,0,10,91,1,0,0,0,12,102,1,0,0,0,14,
	132,1,0,0,0,16,145,1,0,0,0,18,163,1,0,0,0,20,184,1,0,0,0,22,193,1,0,0,0,
	24,214,1,0,0,0,26,241,1,0,0,0,28,273,1,0,0,0,30,275,1,0,0,0,32,277,1,0,
	0,0,34,283,1,0,0,0,36,37,3,2,1,0,37,41,5,1,0,0,38,39,3,4,2,0,39,40,5,2,
	0,0,40,42,1,0,0,0,41,38,1,0,0,0,41,42,1,0,0,0,42,43,1,0,0,0,43,44,3,10,
	5,0,44,45,5,2,0,0,45,46,3,26,13,0,46,53,1,0,0,0,47,49,5,48,0,0,48,47,1,
	0,0,0,49,50,1,0,0,0,50,48,1,0,0,0,50,51,1,0,0,0,51,53,1,0,0,0,52,36,1,0,
	0,0,52,48,1,0,0,0,53,1,1,0,0,0,54,59,5,25,0,0,55,56,5,25,0,0,56,57,5,36,
	0,0,57,59,3,8,4,0,58,54,1,0,0,0,58,55,1,0,0,0,59,3,1,0,0,0,60,61,5,26,0,
	0,61,82,3,18,9,0,62,63,5,28,0,0,63,70,3,16,8,0,64,65,5,3,0,0,65,68,3,16,
	8,0,66,67,5,3,0,0,67,69,3,16,8,0,68,66,1,0,0,0,68,69,1,0,0,0,69,71,1,0,
	0,0,70,64,1,0,0,0,70,71,1,0,0,0,71,73,1,0,0,0,72,74,3,6,3,0,73,72,1,0,0,
	0,73,74,1,0,0,0,74,82,1,0,0,0,75,76,5,30,0,0,76,78,3,32,16,0,77,79,3,6,
	3,0,78,77,1,0,0,0,78,79,1,0,0,0,79,82,1,0,0,0,80,82,5,31,0,0,81,60,1,0,
	0,0,81,62,1,0,0,0,81,75,1,0,0,0,81,80,1,0,0,0,82,5,1,0,0,0,83,84,5,29,0,
	0,84,87,3,18,9,0,85,86,5,35,0,0,86,88,3,18,9,0,87,85,1,0,0,0,87,88,1,0,
	0,0,88,7,1,0,0,0,89,90,3,12,6,0,90,9,1,0,0,0,91,92,3,12,6,0,92,11,1,0,0,
	0,93,94,6,6,-1,0,94,103,3,14,7,0,95,96,5,34,0,0,96,103,3,12,6,4,97,103,
	3,28,14,0,98,99,5,4,0,0,99,100,3,12,6,0,100,101,5,5,0,0,101,103,1,0,0,0,
	102,93,1,0,0,0,102,95,1,0,0,0,102,97,1,0,0,0,102,98,1,0,0,0,103,109,1,0,
	0,0,104,105,10,3,0,0,105,106,7,0,0,0,106,108,3,12,6,4,107,104,1,0,0,0,108,
	111,1,0,0,0,109,107,1,0,0,0,109,110,1,0,0,0,110,13,1,0,0,0,111,109,1,0,
	0,0,112,113,3,22,11,0,113,114,5,24,0,0,114,115,3,22,11,0,115,133,1,0,0,
	0,116,117,3,24,12,0,117,118,5,23,0,0,118,119,3,24,12,0,119,133,1,0,0,0,
	120,121,3,24,12,0,121,122,5,37,0,0,122,123,3,24,12,0,123,133,1,0,0,0,124,
	125,3,16,8,0,125,126,5,24,0,0,126,127,3,16,8,0,127,133,1,0,0,0,128,129,
	3,18,9,0,129,130,5,24,0,0,130,131,3,18,9,0,131,133,1,0,0,0,132,112,1,0,
	0,0,132,116,1,0,0,0,132,120,1,0,0,0,132,124,1,0,0,0,132,128,1,0,0,0,133,
	15,1,0,0,0,134,135,6,8,-1,0,135,136,5,4,0,0,136,137,3,16,8,0,137,138,5,
	5,0,0,138,146,1,0,0,0,139,146,5,45,0,0,140,141,3,18,9,0,141,142,5,6,0,0,
	142,143,3,18,9,0,143,146,1,0,0,0,144,146,3,28,14,0,145,134,1,0,0,0,145,
	139,1,0,0,0,145,140,1,0,0,0,145,144,1,0,0,0,146,152,1,0,0,0,147,148,10,
	2,0,0,148,149,7,1,0,0,149,151,3,16,8,3,150,147,1,0,0,0,151,154,1,0,0,0,
	152,150,1,0,0,0,152,153,1,0,0,0,153,17,1,0,0,0,154,152,1,0,0,0,155,156,
	6,9,-1,0,156,157,5,4,0,0,157,158,3,18,9,0,158,159,5,5,0,0,159,164,1,0,0,
	0,160,164,5,33,0,0,161,164,5,46,0,0,162,164,3,28,14,0,163,155,1,0,0,0,163,
	160,1,0,0,0,163,161,1,0,0,0,163,162,1,0,0,0,164,170,1,0,0,0,165,166,10,
	2,0,0,166,167,7,1,0,0,167,169,3,16,8,0,168,165,1,0,0,0,169,172,1,0,0,0,
	170,168,1,0,0,0,170,171,1,0,0,0,171,19,1,0,0,0,172,170,1,0,0,0,173,185,
	3,12,6,0,174,185,3,16,8,0,175,185,3,18,9,0,176,185,3,22,11,0,177,185,5,
	51,0,0,178,185,5,50,0,0,179,185,3,28,14,0,180,181,5,4,0,0,181,182,3,20,
	10,0,182,183,5,5,0,0,183,185,1,0,0,0,184,173,1,0,0,0,184,174,1,0,0,0,184,
	175,1,0,0,0,184,176,1,0,0,0,184,177,1,0,0,0,184,178,1,0,0,0,184,179,1,0,
	0,0,184,180,1,0,0,0,185,21,1,0,0,0,186,187,6,11,-1,0,187,194,3,28,14,0,
	188,194,5,51,0,0,189,190,5,4,0,0,190,191,3,22,11,0,191,192,5,5,0,0,192,
	194,1,0,0,0,193,186,1,0,0,0,193,188,1,0,0,0,193,189,1,0,0,0,194,203,1,0,
	0,0,195,196,10,5,0,0,196,197,7,2,0,0,197,202,3,22,11,6,198,199,10,4,0,0,
	199,200,7,1,0,0,200,202,3,22,11,5,201,195,1,0,0,0,201,198,1,0,0,0,202,205,
	1,0,0,0,203,201,1,0,0,0,203,204,1,0,0,0,204,23,1,0,0,0,205,203,1,0,0,0,
	206,207,6,12,-1,0,207,208,5,4,0,0,208,209,3,24,12,0,209,210,5,5,0,0,210,
	215,1,0,0,0,211,215,5,50,0,0,212,215,5,46,0,0,213,215,3,28,14,0,214,206,
	1,0,0,0,214,211,1,0,0,0,214,212,1,0,0,0,214,213,1,0,0,0,215,221,1,0,0,0,
	216,217,10,1,0,0,217,218,5,7,0,0,218,220,3,24,12,2,219,216,1,0,0,0,220,
	223,1,0,0,0,221,219,1,0,0,0,221,222,1,0,0,0,222,25,1,0,0,0,223,221,1,0,
	0,0,224,226,9,0,0,0,225,224,1,0,0,0,226,229,1,0,0,0,227,225,1,0,0,0,227,
	228,1,0,0,0,228,242,1,0,0,0,229,227,1,0,0,0,230,242,5,10,0,0,231,242,5,
	11,0,0,232,242,5,12,0,0,233,242,5,13,0,0,234,242,5,14,0,0,235,242,5,15,
	0,0,236,242,5,16,0,0,237,242,5,17,0,0,238,242,5,18,0,0,239,242,5,19,0,0,
	240,242,5,20,0,0,241,227,1,0,0,0,241,230,1,0,0,0,241,231,1,0,0,0,241,232,
	1,0,0,0,241,233,1,0,0,0,241,234,1,0,0,0,241,235,1,0,0,0,241,236,1,0,0,0,
	241,237,1,0,0,0,241,238,1,0,0,0,241,239,1,0,0,0,241,240,1,0,0,0,242,27,
	1,0,0,0,243,274,5,47,0,0,244,245,5,25,0,0,245,246,5,21,0,0,246,274,5,47,
	0,0,247,248,5,47,0,0,248,249,5,4,0,0,249,254,3,34,17,0,250,251,5,22,0,0,
	251,253,3,34,17,0,252,250,1,0,0,0,253,256,1,0,0,0,254,252,1,0,0,0,254,255,
	1,0,0,0,255,257,1,0,0,0,256,254,1,0,0,0,257,258,5,5,0,0,258,274,1,0,0,0,
	259,260,5,25,0,0,260,261,5,21,0,0,261,262,5,47,0,0,262,263,5,4,0,0,263,
	268,3,34,17,0,264,265,5,22,0,0,265,267,3,34,17,0,266,264,1,0,0,0,267,270,
	1,0,0,0,268,266,1,0,0,0,268,269,1,0,0,0,269,271,1,0,0,0,270,268,1,0,0,0,
	271,272,5,5,0,0,272,274,1,0,0,0,273,243,1,0,0,0,273,244,1,0,0,0,273,247,
	1,0,0,0,273,259,1,0,0,0,274,29,1,0,0,0,275,276,7,3,0,0,276,31,1,0,0,0,277,
	278,7,4,0,0,278,33,1,0,0,0,279,284,5,51,0,0,280,284,5,50,0,0,281,284,5,
	45,0,0,282,284,5,46,0,0,283,279,1,0,0,0,283,280,1,0,0,0,283,281,1,0,0,0,
	283,282,1,0,0,0,284,35,1,0,0,0,29,41,50,52,58,68,70,73,78,81,87,102,109,
	132,145,152,163,170,184,193,201,203,214,221,227,241,254,268,273,283];

	private static __ATN: ATN;
	public static get _ATN(): ATN {
		if (!SmartRuleParser.__ATN) {
			SmartRuleParser.__ATN = new ATNDeserializer().deserialize(SmartRuleParser._serializedATN);
		}

		return SmartRuleParser.__ATN;
	}


	static DecisionsToDFA = SmartRuleParser._ATN.decisionToState.map( (ds: DecisionState, index: number) => new DFA(ds, index) );

}

export class SsmruleContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_ssmrule;
	}
	public override copyFrom(ctx: SsmruleContext): void {
		super.copyFrom(ctx);
	}
}
export class RuleLineContext extends SsmruleContext {
	constructor(parser: SmartRuleParser, ctx: SsmruleContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public object(): ObjectContext {
		return this.getTypedRuleContext(ObjectContext, 0) as ObjectContext;
	}
	public conditions(): ConditionsContext {
		return this.getTypedRuleContext(ConditionsContext, 0) as ConditionsContext;
	}
	public cmdlet(): CmdletContext {
		return this.getTypedRuleContext(CmdletContext, 0) as CmdletContext;
	}
	public trigger(): TriggerContext {
		return this.getTypedRuleContext(TriggerContext, 0) as TriggerContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterRuleLine) {
	 		listener.enterRuleLine(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitRuleLine) {
	 		listener.exitRuleLine(this);
		}
	}
}
export class CommentLineContext extends SsmruleContext {
	constructor(parser: SmartRuleParser, ctx: SsmruleContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public Linecomment_list(): TerminalNode[] {
	    	return this.getTokens(SmartRuleParser.Linecomment);
	}
	public Linecomment(i: number): TerminalNode {
		return this.getToken(SmartRuleParser.Linecomment, i);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterCommentLine) {
	 		listener.enterCommentLine(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitCommentLine) {
	 		listener.exitCommentLine(this);
		}
	}
}


export class ObjectContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_object;
	}
	public override copyFrom(ctx: ObjectContext): void {
		super.copyFrom(ctx);
	}
}
export class ObjTypeOnlyContext extends ObjectContext {
	constructor(parser: SmartRuleParser, ctx: ObjectContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public OBJECTTYPE(): TerminalNode {
		return this.getToken(SmartRuleParser.OBJECTTYPE, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterObjTypeOnly) {
	 		listener.enterObjTypeOnly(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitObjTypeOnly) {
	 		listener.exitObjTypeOnly(this);
		}
	}
}
export class ObjTypeWithContext extends ObjectContext {
	constructor(parser: SmartRuleParser, ctx: ObjectContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public OBJECTTYPE(): TerminalNode {
		return this.getToken(SmartRuleParser.OBJECTTYPE, 0);
	}
	public WITH(): TerminalNode {
		return this.getToken(SmartRuleParser.WITH, 0);
	}
	public objfilter(): ObjfilterContext {
		return this.getTypedRuleContext(ObjfilterContext, 0) as ObjfilterContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterObjTypeWith) {
	 		listener.enterObjTypeWith(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitObjTypeWith) {
	 		listener.exitObjTypeWith(this);
		}
	}
}


export class TriggerContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_trigger;
	}
	public override copyFrom(ctx: TriggerContext): void {
		super.copyFrom(ctx);
	}
}
export class TriOnceContext extends TriggerContext {
	constructor(parser: SmartRuleParser, ctx: TriggerContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public ONCE(): TerminalNode {
		return this.getToken(SmartRuleParser.ONCE, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterTriOnce) {
	 		listener.enterTriOnce(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitTriOnce) {
	 		listener.exitTriOnce(this);
		}
	}
}
export class TriFileEventContext extends TriggerContext {
	constructor(parser: SmartRuleParser, ctx: TriggerContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public ON(): TerminalNode {
		return this.getToken(SmartRuleParser.ON, 0);
	}
	public fileEvent(): FileEventContext {
		return this.getTypedRuleContext(FileEventContext, 0) as FileEventContext;
	}
	public duringexpr(): DuringexprContext {
		return this.getTypedRuleContext(DuringexprContext, 0) as DuringexprContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterTriFileEvent) {
	 		listener.enterTriFileEvent(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitTriFileEvent) {
	 		listener.exitTriFileEvent(this);
		}
	}
}
export class TriTimePointContext extends TriggerContext {
	constructor(parser: SmartRuleParser, ctx: TriggerContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public AT(): TerminalNode {
		return this.getToken(SmartRuleParser.AT, 0);
	}
	public timepointexpr(): TimepointexprContext {
		return this.getTypedRuleContext(TimepointexprContext, 0) as TimepointexprContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterTriTimePoint) {
	 		listener.enterTriTimePoint(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitTriTimePoint) {
	 		listener.exitTriTimePoint(this);
		}
	}
}
export class TriCycleContext extends TriggerContext {
	constructor(parser: SmartRuleParser, ctx: TriggerContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public EVERY(): TerminalNode {
		return this.getToken(SmartRuleParser.EVERY, 0);
	}
	public timeintvalexpr_list(): TimeintvalexprContext[] {
		return this.getTypedRuleContexts(TimeintvalexprContext) as TimeintvalexprContext[];
	}
	public timeintvalexpr(i: number): TimeintvalexprContext {
		return this.getTypedRuleContext(TimeintvalexprContext, i) as TimeintvalexprContext;
	}
	public duringexpr(): DuringexprContext {
		return this.getTypedRuleContext(DuringexprContext, 0) as DuringexprContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterTriCycle) {
	 		listener.enterTriCycle(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitTriCycle) {
	 		listener.exitTriCycle(this);
		}
	}
}


export class DuringexprContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
	public FROM(): TerminalNode {
		return this.getToken(SmartRuleParser.FROM, 0);
	}
	public timepointexpr_list(): TimepointexprContext[] {
		return this.getTypedRuleContexts(TimepointexprContext) as TimepointexprContext[];
	}
	public timepointexpr(i: number): TimepointexprContext {
		return this.getTypedRuleContext(TimepointexprContext, i) as TimepointexprContext;
	}
	public TO(): TerminalNode {
		return this.getToken(SmartRuleParser.TO, 0);
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_duringexpr;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterDuringexpr) {
	 		listener.enterDuringexpr(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitDuringexpr) {
	 		listener.exitDuringexpr(this);
		}
	}
}


export class ObjfilterContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
	public boolvalue(): BoolvalueContext {
		return this.getTypedRuleContext(BoolvalueContext, 0) as BoolvalueContext;
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_objfilter;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterObjfilter) {
	 		listener.enterObjfilter(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitObjfilter) {
	 		listener.exitObjfilter(this);
		}
	}
}


export class ConditionsContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
	public boolvalue(): BoolvalueContext {
		return this.getTypedRuleContext(BoolvalueContext, 0) as BoolvalueContext;
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_conditions;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterConditions) {
	 		listener.enterConditions(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitConditions) {
	 		listener.exitConditions(this);
		}
	}
}


export class BoolvalueContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_boolvalue;
	}
	public override copyFrom(ctx: BoolvalueContext): void {
		super.copyFrom(ctx);
	}
}
export class BvAndORContext extends BoolvalueContext {
	constructor(parser: SmartRuleParser, ctx: BoolvalueContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public boolvalue_list(): BoolvalueContext[] {
		return this.getTypedRuleContexts(BoolvalueContext) as BoolvalueContext[];
	}
	public boolvalue(i: number): BoolvalueContext {
		return this.getTypedRuleContext(BoolvalueContext, i) as BoolvalueContext;
	}
	public AND(): TerminalNode {
		return this.getToken(SmartRuleParser.AND, 0);
	}
	public OR(): TerminalNode {
		return this.getToken(SmartRuleParser.OR, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterBvAndOR) {
	 		listener.enterBvAndOR(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitBvAndOR) {
	 		listener.exitBvAndOR(this);
		}
	}
}
export class BvIdContext extends BoolvalueContext {
	constructor(parser: SmartRuleParser, ctx: BoolvalueContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public id(): IdContext {
		return this.getTypedRuleContext(IdContext, 0) as IdContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterBvId) {
	 		listener.enterBvId(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitBvId) {
	 		listener.exitBvId(this);
		}
	}
}
export class BvNotContext extends BoolvalueContext {
	constructor(parser: SmartRuleParser, ctx: BoolvalueContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public NOT(): TerminalNode {
		return this.getToken(SmartRuleParser.NOT, 0);
	}
	public boolvalue(): BoolvalueContext {
		return this.getTypedRuleContext(BoolvalueContext, 0) as BoolvalueContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterBvNot) {
	 		listener.enterBvNot(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitBvNot) {
	 		listener.exitBvNot(this);
		}
	}
}
export class BvCompareexprContext extends BoolvalueContext {
	constructor(parser: SmartRuleParser, ctx: BoolvalueContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public compareexpr(): CompareexprContext {
		return this.getTypedRuleContext(CompareexprContext, 0) as CompareexprContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterBvCompareexpr) {
	 		listener.enterBvCompareexpr(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitBvCompareexpr) {
	 		listener.exitBvCompareexpr(this);
		}
	}
}
export class BvCurveContext extends BoolvalueContext {
	constructor(parser: SmartRuleParser, ctx: BoolvalueContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public boolvalue(): BoolvalueContext {
		return this.getTypedRuleContext(BoolvalueContext, 0) as BoolvalueContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterBvCurve) {
	 		listener.enterBvCurve(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitBvCurve) {
	 		listener.exitBvCurve(this);
		}
	}
}


export class CompareexprContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_compareexpr;
	}
	public override copyFrom(ctx: CompareexprContext): void {
		super.copyFrom(ctx);
	}
}
export class CmpTimeintvalTimeintvalContext extends CompareexprContext {
	constructor(parser: SmartRuleParser, ctx: CompareexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public timeintvalexpr_list(): TimeintvalexprContext[] {
		return this.getTypedRuleContexts(TimeintvalexprContext) as TimeintvalexprContext[];
	}
	public timeintvalexpr(i: number): TimeintvalexprContext {
		return this.getTypedRuleContext(TimeintvalexprContext, i) as TimeintvalexprContext;
	}
	public OPCMP(): TerminalNode {
		return this.getToken(SmartRuleParser.OPCMP, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterCmpTimeintvalTimeintval) {
	 		listener.enterCmpTimeintvalTimeintval(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitCmpTimeintvalTimeintval) {
	 		listener.exitCmpTimeintvalTimeintval(this);
		}
	}
}
export class CmpIdStringContext extends CompareexprContext {
	constructor(parser: SmartRuleParser, ctx: CompareexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public stringexpr_list(): StringexprContext[] {
		return this.getTypedRuleContexts(StringexprContext) as StringexprContext[];
	}
	public stringexpr(i: number): StringexprContext {
		return this.getTypedRuleContext(StringexprContext, i) as StringexprContext;
	}
	public OPEQCMP(): TerminalNode {
		return this.getToken(SmartRuleParser.OPEQCMP, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterCmpIdString) {
	 		listener.enterCmpIdString(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitCmpIdString) {
	 		listener.exitCmpIdString(this);
		}
	}
}
export class CmpIdLongContext extends CompareexprContext {
	constructor(parser: SmartRuleParser, ctx: CompareexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public numricexpr_list(): NumricexprContext[] {
		return this.getTypedRuleContexts(NumricexprContext) as NumricexprContext[];
	}
	public numricexpr(i: number): NumricexprContext {
		return this.getTypedRuleContext(NumricexprContext, i) as NumricexprContext;
	}
	public OPCMP(): TerminalNode {
		return this.getToken(SmartRuleParser.OPCMP, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterCmpIdLong) {
	 		listener.enterCmpIdLong(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitCmpIdLong) {
	 		listener.exitCmpIdLong(this);
		}
	}
}
export class CmpTimepointTimePointContext extends CompareexprContext {
	constructor(parser: SmartRuleParser, ctx: CompareexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public timepointexpr_list(): TimepointexprContext[] {
		return this.getTypedRuleContexts(TimepointexprContext) as TimepointexprContext[];
	}
	public timepointexpr(i: number): TimepointexprContext {
		return this.getTypedRuleContext(TimepointexprContext, i) as TimepointexprContext;
	}
	public OPCMP(): TerminalNode {
		return this.getToken(SmartRuleParser.OPCMP, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterCmpTimepointTimePoint) {
	 		listener.enterCmpTimepointTimePoint(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitCmpTimepointTimePoint) {
	 		listener.exitCmpTimepointTimePoint(this);
		}
	}
}
export class CmpIdStringMatchesContext extends CompareexprContext {
	constructor(parser: SmartRuleParser, ctx: CompareexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public stringexpr_list(): StringexprContext[] {
		return this.getTypedRuleContexts(StringexprContext) as StringexprContext[];
	}
	public stringexpr(i: number): StringexprContext {
		return this.getTypedRuleContext(StringexprContext, i) as StringexprContext;
	}
	public MATCHES(): TerminalNode {
		return this.getToken(SmartRuleParser.MATCHES, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterCmpIdStringMatches) {
	 		listener.enterCmpIdStringMatches(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitCmpIdStringMatches) {
	 		listener.exitCmpIdStringMatches(this);
		}
	}
}


export class TimeintvalexprContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_timeintvalexpr;
	}
	public override copyFrom(ctx: TimeintvalexprContext): void {
		super.copyFrom(ctx);
	}
}
export class TieTiIdExprContext extends TimeintvalexprContext {
	constructor(parser: SmartRuleParser, ctx: TimeintvalexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public id(): IdContext {
		return this.getTypedRuleContext(IdContext, 0) as IdContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterTieTiIdExpr) {
	 		listener.enterTieTiIdExpr(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitTieTiIdExpr) {
	 		listener.exitTieTiIdExpr(this);
		}
	}
}
export class TieTpExprContext extends TimeintvalexprContext {
	constructor(parser: SmartRuleParser, ctx: TimeintvalexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public timepointexpr_list(): TimepointexprContext[] {
		return this.getTypedRuleContexts(TimepointexprContext) as TimepointexprContext[];
	}
	public timepointexpr(i: number): TimepointexprContext {
		return this.getTypedRuleContext(TimepointexprContext, i) as TimepointexprContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterTieTpExpr) {
	 		listener.enterTieTpExpr(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitTieTpExpr) {
	 		listener.exitTieTpExpr(this);
		}
	}
}
export class TieConstContext extends TimeintvalexprContext {
	constructor(parser: SmartRuleParser, ctx: TimeintvalexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public TIMEINTVALCONST(): TerminalNode {
		return this.getToken(SmartRuleParser.TIMEINTVALCONST, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterTieConst) {
	 		listener.enterTieConst(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitTieConst) {
	 		listener.exitTieConst(this);
		}
	}
}
export class TieTiExprContext extends TimeintvalexprContext {
	constructor(parser: SmartRuleParser, ctx: TimeintvalexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public timeintvalexpr_list(): TimeintvalexprContext[] {
		return this.getTypedRuleContexts(TimeintvalexprContext) as TimeintvalexprContext[];
	}
	public timeintvalexpr(i: number): TimeintvalexprContext {
		return this.getTypedRuleContext(TimeintvalexprContext, i) as TimeintvalexprContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterTieTiExpr) {
	 		listener.enterTieTiExpr(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitTieTiExpr) {
	 		listener.exitTieTiExpr(this);
		}
	}
}
export class TieCurvesContext extends TimeintvalexprContext {
	constructor(parser: SmartRuleParser, ctx: TimeintvalexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public timeintvalexpr(): TimeintvalexprContext {
		return this.getTypedRuleContext(TimeintvalexprContext, 0) as TimeintvalexprContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterTieCurves) {
	 		listener.enterTieCurves(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitTieCurves) {
	 		listener.exitTieCurves(this);
		}
	}
}


export class TimepointexprContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_timepointexpr;
	}
	public override copyFrom(ctx: TimepointexprContext): void {
		super.copyFrom(ctx);
	}
}
export class TpeNowContext extends TimepointexprContext {
	constructor(parser: SmartRuleParser, ctx: TimepointexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public NOW(): TerminalNode {
		return this.getToken(SmartRuleParser.NOW, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterTpeNow) {
	 		listener.enterTpeNow(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitTpeNow) {
	 		listener.exitTpeNow(this);
		}
	}
}
export class TpeTimeConstContext extends TimepointexprContext {
	constructor(parser: SmartRuleParser, ctx: TimepointexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public TIMEPOINTCONST(): TerminalNode {
		return this.getToken(SmartRuleParser.TIMEPOINTCONST, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterTpeTimeConst) {
	 		listener.enterTpeTimeConst(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitTpeTimeConst) {
	 		listener.exitTpeTimeConst(this);
		}
	}
}
export class TpeTimeExprContext extends TimepointexprContext {
	constructor(parser: SmartRuleParser, ctx: TimepointexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public timepointexpr(): TimepointexprContext {
		return this.getTypedRuleContext(TimepointexprContext, 0) as TimepointexprContext;
	}
	public timeintvalexpr(): TimeintvalexprContext {
		return this.getTypedRuleContext(TimeintvalexprContext, 0) as TimeintvalexprContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterTpeTimeExpr) {
	 		listener.enterTpeTimeExpr(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitTpeTimeExpr) {
	 		listener.exitTpeTimeExpr(this);
		}
	}
}
export class TpeCurvesContext extends TimepointexprContext {
	constructor(parser: SmartRuleParser, ctx: TimepointexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public timepointexpr(): TimepointexprContext {
		return this.getTypedRuleContext(TimepointexprContext, 0) as TimepointexprContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterTpeCurves) {
	 		listener.enterTpeCurves(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitTpeCurves) {
	 		listener.exitTpeCurves(this);
		}
	}
}
export class TpeTimeIdContext extends TimepointexprContext {
	constructor(parser: SmartRuleParser, ctx: TimepointexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public id(): IdContext {
		return this.getTypedRuleContext(IdContext, 0) as IdContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterTpeTimeId) {
	 		listener.enterTpeTimeId(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitTpeTimeId) {
	 		listener.exitTpeTimeId(this);
		}
	}
}


export class CommonexprContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
	public boolvalue(): BoolvalueContext {
		return this.getTypedRuleContext(BoolvalueContext, 0) as BoolvalueContext;
	}
	public timeintvalexpr(): TimeintvalexprContext {
		return this.getTypedRuleContext(TimeintvalexprContext, 0) as TimeintvalexprContext;
	}
	public timepointexpr(): TimepointexprContext {
		return this.getTypedRuleContext(TimepointexprContext, 0) as TimepointexprContext;
	}
	public numricexpr(): NumricexprContext {
		return this.getTypedRuleContext(NumricexprContext, 0) as NumricexprContext;
	}
	public LONG(): TerminalNode {
		return this.getToken(SmartRuleParser.LONG, 0);
	}
	public STRING(): TerminalNode {
		return this.getToken(SmartRuleParser.STRING, 0);
	}
	public id(): IdContext {
		return this.getTypedRuleContext(IdContext, 0) as IdContext;
	}
	public commonexpr(): CommonexprContext {
		return this.getTypedRuleContext(CommonexprContext, 0) as CommonexprContext;
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_commonexpr;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterCommonexpr) {
	 		listener.enterCommonexpr(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitCommonexpr) {
	 		listener.exitCommonexpr(this);
		}
	}
}


export class NumricexprContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_numricexpr;
	}
	public override copyFrom(ctx: NumricexprContext): void {
		super.copyFrom(ctx);
	}
}
export class NumricexprIdContext extends NumricexprContext {
	constructor(parser: SmartRuleParser, ctx: NumricexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public id(): IdContext {
		return this.getTypedRuleContext(IdContext, 0) as IdContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterNumricexprId) {
	 		listener.enterNumricexprId(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitNumricexprId) {
	 		listener.exitNumricexprId(this);
		}
	}
}
export class NumricexprCurveContext extends NumricexprContext {
	constructor(parser: SmartRuleParser, ctx: NumricexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public numricexpr(): NumricexprContext {
		return this.getTypedRuleContext(NumricexprContext, 0) as NumricexprContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterNumricexprCurve) {
	 		listener.enterNumricexprCurve(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitNumricexprCurve) {
	 		listener.exitNumricexprCurve(this);
		}
	}
}
export class NumricexprAddContext extends NumricexprContext {
	public _op!: Token;
	constructor(parser: SmartRuleParser, ctx: NumricexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public numricexpr_list(): NumricexprContext[] {
		return this.getTypedRuleContexts(NumricexprContext) as NumricexprContext[];
	}
	public numricexpr(i: number): NumricexprContext {
		return this.getTypedRuleContext(NumricexprContext, i) as NumricexprContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterNumricexprAdd) {
	 		listener.enterNumricexprAdd(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitNumricexprAdd) {
	 		listener.exitNumricexprAdd(this);
		}
	}
}
export class NumricexprMulContext extends NumricexprContext {
	public _op!: Token;
	constructor(parser: SmartRuleParser, ctx: NumricexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public numricexpr_list(): NumricexprContext[] {
		return this.getTypedRuleContexts(NumricexprContext) as NumricexprContext[];
	}
	public numricexpr(i: number): NumricexprContext {
		return this.getTypedRuleContext(NumricexprContext, i) as NumricexprContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterNumricexprMul) {
	 		listener.enterNumricexprMul(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitNumricexprMul) {
	 		listener.exitNumricexprMul(this);
		}
	}
}
export class NumricexprLongContext extends NumricexprContext {
	constructor(parser: SmartRuleParser, ctx: NumricexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public LONG(): TerminalNode {
		return this.getToken(SmartRuleParser.LONG, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterNumricexprLong) {
	 		listener.enterNumricexprLong(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitNumricexprLong) {
	 		listener.exitNumricexprLong(this);
		}
	}
}


export class StringexprContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_stringexpr;
	}
	public override copyFrom(ctx: StringexprContext): void {
		super.copyFrom(ctx);
	}
}
export class StrPlusContext extends StringexprContext {
	constructor(parser: SmartRuleParser, ctx: StringexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public stringexpr_list(): StringexprContext[] {
		return this.getTypedRuleContexts(StringexprContext) as StringexprContext[];
	}
	public stringexpr(i: number): StringexprContext {
		return this.getTypedRuleContext(StringexprContext, i) as StringexprContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterStrPlus) {
	 		listener.enterStrPlus(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitStrPlus) {
	 		listener.exitStrPlus(this);
		}
	}
}
export class StrOrdStringContext extends StringexprContext {
	constructor(parser: SmartRuleParser, ctx: StringexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public STRING(): TerminalNode {
		return this.getToken(SmartRuleParser.STRING, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterStrOrdString) {
	 		listener.enterStrOrdString(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitStrOrdString) {
	 		listener.exitStrOrdString(this);
		}
	}
}
export class StrIDContext extends StringexprContext {
	constructor(parser: SmartRuleParser, ctx: StringexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public id(): IdContext {
		return this.getTypedRuleContext(IdContext, 0) as IdContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterStrID) {
	 		listener.enterStrID(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitStrID) {
	 		listener.exitStrID(this);
		}
	}
}
export class StrCurveContext extends StringexprContext {
	constructor(parser: SmartRuleParser, ctx: StringexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public stringexpr(): StringexprContext {
		return this.getTypedRuleContext(StringexprContext, 0) as StringexprContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterStrCurve) {
	 		listener.enterStrCurve(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitStrCurve) {
	 		listener.exitStrCurve(this);
		}
	}
}
export class StrTimePointStrContext extends StringexprContext {
	constructor(parser: SmartRuleParser, ctx: StringexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public TIMEPOINTCONST(): TerminalNode {
		return this.getToken(SmartRuleParser.TIMEPOINTCONST, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterStrTimePointStr) {
	 		listener.enterStrTimePointStr(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitStrTimePointStr) {
	 		listener.exitStrTimePointStr(this);
		}
	}
}


export class CmdletContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_cmdlet;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterCmdlet) {
	 		listener.enterCmdlet(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitCmdlet) {
	 		listener.exitCmdlet(this);
		}
	}
}


export class IdContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_id;
	}
	public override copyFrom(ctx: IdContext): void {
		super.copyFrom(ctx);
	}
}
export class IdAttContext extends IdContext {
	constructor(parser: SmartRuleParser, ctx: IdContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public ID(): TerminalNode {
		return this.getToken(SmartRuleParser.ID, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterIdAtt) {
	 		listener.enterIdAtt(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitIdAtt) {
	 		listener.exitIdAtt(this);
		}
	}
}
export class IdAttParaContext extends IdContext {
	constructor(parser: SmartRuleParser, ctx: IdContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public ID(): TerminalNode {
		return this.getToken(SmartRuleParser.ID, 0);
	}
	public constexpr_list(): ConstexprContext[] {
		return this.getTypedRuleContexts(ConstexprContext) as ConstexprContext[];
	}
	public constexpr(i: number): ConstexprContext {
		return this.getTypedRuleContext(ConstexprContext, i) as ConstexprContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterIdAttPara) {
	 		listener.enterIdAttPara(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitIdAttPara) {
	 		listener.exitIdAttPara(this);
		}
	}
}
export class IdObjAttContext extends IdContext {
	constructor(parser: SmartRuleParser, ctx: IdContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public OBJECTTYPE(): TerminalNode {
		return this.getToken(SmartRuleParser.OBJECTTYPE, 0);
	}
	public ID(): TerminalNode {
		return this.getToken(SmartRuleParser.ID, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterIdObjAtt) {
	 		listener.enterIdObjAtt(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitIdObjAtt) {
	 		listener.exitIdObjAtt(this);
		}
	}
}
export class IdObjAttParaContext extends IdContext {
	constructor(parser: SmartRuleParser, ctx: IdContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public OBJECTTYPE(): TerminalNode {
		return this.getToken(SmartRuleParser.OBJECTTYPE, 0);
	}
	public ID(): TerminalNode {
		return this.getToken(SmartRuleParser.ID, 0);
	}
	public constexpr_list(): ConstexprContext[] {
		return this.getTypedRuleContexts(ConstexprContext) as ConstexprContext[];
	}
	public constexpr(i: number): ConstexprContext {
		return this.getTypedRuleContext(ConstexprContext, i) as ConstexprContext;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterIdObjAttPara) {
	 		listener.enterIdObjAttPara(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitIdObjAttPara) {
	 		listener.exitIdObjAttPara(this);
		}
	}
}


export class OprContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_opr;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterOpr) {
	 		listener.enterOpr(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitOpr) {
	 		listener.exitOpr(this);
		}
	}
}


export class FileEventContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
	public FILECREATE(): TerminalNode {
		return this.getToken(SmartRuleParser.FILECREATE, 0);
	}
	public FILECLOSE(): TerminalNode {
		return this.getToken(SmartRuleParser.FILECLOSE, 0);
	}
	public FILEAPPEND(): TerminalNode {
		return this.getToken(SmartRuleParser.FILEAPPEND, 0);
	}
	public FILERENAME(): TerminalNode {
		return this.getToken(SmartRuleParser.FILERENAME, 0);
	}
	public FILEMETADATA(): TerminalNode {
		return this.getToken(SmartRuleParser.FILEMETADATA, 0);
	}
	public FILEUNLINK(): TerminalNode {
		return this.getToken(SmartRuleParser.FILEUNLINK, 0);
	}
	public FILETRUNCATE(): TerminalNode {
		return this.getToken(SmartRuleParser.FILETRUNCATE, 0);
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_fileEvent;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterFileEvent) {
	 		listener.enterFileEvent(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitFileEvent) {
	 		listener.exitFileEvent(this);
		}
	}
}


export class ConstexprContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_constexpr;
	}
	public override copyFrom(ctx: ConstexprContext): void {
		super.copyFrom(ctx);
	}
}
export class ConstStringContext extends ConstexprContext {
	constructor(parser: SmartRuleParser, ctx: ConstexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public STRING(): TerminalNode {
		return this.getToken(SmartRuleParser.STRING, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterConstString) {
	 		listener.enterConstString(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitConstString) {
	 		listener.exitConstString(this);
		}
	}
}
export class ConstLongContext extends ConstexprContext {
	constructor(parser: SmartRuleParser, ctx: ConstexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public LONG(): TerminalNode {
		return this.getToken(SmartRuleParser.LONG, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterConstLong) {
	 		listener.enterConstLong(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitConstLong) {
	 		listener.exitConstLong(this);
		}
	}
}
export class ConstTimePointContext extends ConstexprContext {
	constructor(parser: SmartRuleParser, ctx: ConstexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public TIMEPOINTCONST(): TerminalNode {
		return this.getToken(SmartRuleParser.TIMEPOINTCONST, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterConstTimePoint) {
	 		listener.enterConstTimePoint(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitConstTimePoint) {
	 		listener.exitConstTimePoint(this);
		}
	}
}
export class ConstTimeInvervalContext extends ConstexprContext {
	constructor(parser: SmartRuleParser, ctx: ConstexprContext) {
		super(parser, ctx.parentCtx, ctx.invokingState);
		super.copyFrom(ctx);
	}
	public TIMEINTVALCONST(): TerminalNode {
		return this.getToken(SmartRuleParser.TIMEINTVALCONST, 0);
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterConstTimeInverval) {
	 		listener.enterConstTimeInverval(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitConstTimeInverval) {
	 		listener.exitConstTimeInverval(this);
		}
	}
}
