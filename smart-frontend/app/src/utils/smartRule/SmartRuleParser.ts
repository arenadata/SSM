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
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable prettier/prettier */

// Generated from SmartRule.g4 by ANTLR 4.13.2
// noinspection ES6UnusedImports,JSUnusedGlobalSymbols,JSUnusedLocalSymbols

import type { DecisionState,
	RuleContext,
	TerminalNode, TokenStream } from 'antlr4';
import {
	ATN,
	ATNDeserializer, DFA, FailedPredicateException,
	RecognitionException, NoViableAltException, BailErrorStrategy,
	Parser, ParserATNSimulator, ParserRuleContext, PredictionMode, PredictionContextCache, RuleNode,
	Token,
	Interval, IntervalSet,
} from 'antlr4';
import type SmartRuleListener from './SmartRuleListener.js';
// for running tests with parameters, TODO: discuss strategy for typed parameters in CI
 
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
	public static readonly T__22 = 23;
	public static readonly T__23 = 24;
	public static readonly T__24 = 25;
	public static readonly T__25 = 26;
	public static readonly T__26 = 27;
	public static readonly T__27 = 28;
	public static readonly OBJECTTYPE = 29;
	public static readonly AT = 30;
	public static readonly AND = 31;
	public static readonly EVERY = 32;
	public static readonly FROM = 33;
	public static readonly ON = 34;
	public static readonly ONCE = 35;
	public static readonly OR = 36;
	public static readonly NOW = 37;
	public static readonly NOT = 38;
	public static readonly TO = 39;
	public static readonly WITH = 40;
	public static readonly MATCHES = 41;
	public static readonly FILECREATE = 42;
	public static readonly FILECLOSE = 43;
	public static readonly FILEAPPEND = 44;
	public static readonly FILERENAME = 45;
	public static readonly FILEMETADATA = 46;
	public static readonly FILEUNLINK = 47;
	public static readonly FILETRUNCATE = 48;
	public static readonly TIMEINTVALCONST = 49;
	public static readonly TIMEPOINTCONST = 50;
	public static readonly ID = 51;
	public static readonly Linecomment = 52;
	public static readonly WS = 53;
	public static readonly STRING = 54;
	public static readonly LONG = 55;
	public static readonly NEWLINE = 56;
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
	public static readonly RULE_oPCMP = 15;
	public static readonly RULE_opr = 16;
	public static readonly RULE_fileEvent = 17;
	public static readonly RULE_constexpr = 18;
	public static readonly literalNames: (string | null)[] = [ null, '\':\'', 
                                                            '\'|\'', '\'/\'', 
                                                            '\'(\'', '\')\'', 
                                                            '\'==\'', '\'!=\'', 
                                                            '\'-\'', '\'+\'', 
                                                            '\'*\'', '\'%\'', 
                                                            '\';\'', '\'@\'', 
                                                            '\'$\'', '\'&\'', 
                                                            '\'=\'', '\'{\'', 
                                                            '\'}\'', '\'[\'', 
                                                            '\']\'', '\'"\'', 
                                                            '\'?\'', '\'.\'', 
                                                            '\',\'', '\'>\'', 
                                                            '\'<\'', '\'>=\'', 
                                                            '\'<=\'', null, 
                                                            '\'at\'', '\'and\'', 
                                                            '\'every\'', '\'from\'', 
                                                            '\'on\'', '\'once\'', 
                                                            '\'or\'', '\'now\'', 
                                                            '\'not\'', '\'to\'', 
                                                            '\'with\'', '\'matches\'', 
                                                            '\'FileCreate\'', 
                                                            '\'FileClose\'', 
                                                            '\'FileAppend\'', 
                                                            '\'FileRename\'', 
                                                            '\'FileMetadate\'', 
                                                            '\'FileUnlink\'', 
                                                            '\'FileTruncate\'' ];
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
                                                             null, null, 
                                                             null, null, 
                                                             null, null, 
                                                             null, 'OBJECTTYPE', 
                                                             'AT', 'AND', 
                                                             'EVERY', 'FROM', 
                                                             'ON', 'ONCE', 
                                                             'OR', 'NOW', 
                                                             'NOT', 'TO', 
                                                             'WITH', 'MATCHES', 
                                                             'FILECREATE', 
                                                             'FILECLOSE', 
                                                             'FILEAPPEND', 
                                                             'FILERENAME', 
                                                             'FILEMETADATA', 
                                                             'FILEUNLINK', 
                                                             'FILETRUNCATE', 
                                                             'TIMEINTVALCONST', 
                                                             'TIMEPOINTCONST', 
                                                             'ID', 'Linecomment', 
                                                             'WS', 'STRING', 
                                                             'LONG', 'NEWLINE' ];
	// tslint:disable:no-trailing-whitespace
	public static readonly ruleNames: string[] = [
		'ssmrule', 'object', 'trigger', 'duringexpr', 'objfilter', 'conditions', 
		'boolvalue', 'compareexpr', 'timeintvalexpr', 'timepointexpr', 'commonexpr', 
		'numricexpr', 'stringexpr', 'cmdlet', 'id', 'oPCMP', 'opr', 'fileEvent', 
		'constexpr',
	];
	public get grammarFileName(): string { return 'SmartRule.g4'; }
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
			this.state = 54;
			this._errHandler.sync(this);
			switch (this._input.LA(1)) {
			case 29:
				localctx = new RuleLineContext(this, localctx);
				this.enterOuterAlt(localctx, 1);
				{
				this.state = 38;
				this.object();
				this.state = 39;
				this.match(SmartRuleParser.T__0);
				this.state = 43;
				this._errHandler.sync(this);
				_la = this._input.LA(1);
				if (((((_la - 30)) & ~0x1F) === 0 && ((1 << (_la - 30)) & 53) !== 0)) {
					{
					this.state = 40;
					this.trigger();
					this.state = 41;
					this.match(SmartRuleParser.T__1);
					}
				}

				this.state = 45;
				this.conditions();
				this.state = 46;
				this.match(SmartRuleParser.T__1);
				this.state = 47;
				this.cmdlet();
				}
				break;
			case 52:
				localctx = new CommentLineContext(this, localctx);
				this.enterOuterAlt(localctx, 2);
				{
				this.state = 50;
				this._errHandler.sync(this);
				_la = this._input.LA(1);
				do {
					{
					{
					this.state = 49;
					this.match(SmartRuleParser.Linecomment);
					}
					}
					this.state = 52;
					this._errHandler.sync(this);
					_la = this._input.LA(1);
				} while (_la===52);
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
			this.state = 60;
			this._errHandler.sync(this);
			switch ( this._interp.adaptivePredict(this._input, 3, this._ctx) ) {
			case 1:
				localctx = new ObjTypeOnlyContext(this, localctx);
				this.enterOuterAlt(localctx, 1);
				{
				this.state = 56;
				this.match(SmartRuleParser.OBJECTTYPE);
				}
				break;
			case 2:
				localctx = new ObjTypeWithContext(this, localctx);
				this.enterOuterAlt(localctx, 2);
				{
				this.state = 57;
				this.match(SmartRuleParser.OBJECTTYPE);
				this.state = 58;
				this.match(SmartRuleParser.WITH);
				this.state = 59;
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
			this.state = 83;
			this._errHandler.sync(this);
			switch (this._input.LA(1)) {
			case 30:
				localctx = new TriTimePointContext(this, localctx);
				this.enterOuterAlt(localctx, 1);
				{
				this.state = 62;
				this.match(SmartRuleParser.AT);
				this.state = 63;
				this.timepointexpr(0);
				}
				break;
			case 32:
				localctx = new TriCycleContext(this, localctx);
				this.enterOuterAlt(localctx, 2);
				{
				this.state = 64;
				this.match(SmartRuleParser.EVERY);
				this.state = 65;
				this.timeintvalexpr(0);
				this.state = 72;
				this._errHandler.sync(this);
				_la = this._input.LA(1);
				if (_la===3) {
					{
					this.state = 66;
					this.match(SmartRuleParser.T__2);
					this.state = 67;
					this.timeintvalexpr(0);
					this.state = 70;
					this._errHandler.sync(this);
					_la = this._input.LA(1);
					if (_la===3) {
						{
						this.state = 68;
						this.match(SmartRuleParser.T__2);
						this.state = 69;
						this.timeintvalexpr(0);
						}
					}

					}
				}

				this.state = 75;
				this._errHandler.sync(this);
				_la = this._input.LA(1);
				if (_la===33) {
					{
					this.state = 74;
					this.duringexpr();
					}
				}

				}
				break;
			case 34:
				localctx = new TriFileEventContext(this, localctx);
				this.enterOuterAlt(localctx, 3);
				{
				this.state = 77;
				this.match(SmartRuleParser.ON);
				this.state = 78;
				this.fileEvent();
				this.state = 80;
				this._errHandler.sync(this);
				_la = this._input.LA(1);
				if (_la===33) {
					{
					this.state = 79;
					this.duringexpr();
					}
				}

				}
				break;
			case 35:
				localctx = new TriOnceContext(this, localctx);
				this.enterOuterAlt(localctx, 4);
				{
				this.state = 82;
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
		const localctx: DuringexprContext = new DuringexprContext(this, this._ctx, this.state);
		this.enterRule(localctx, 6, SmartRuleParser.RULE_duringexpr);
		let _la: number;
		try {
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 85;
			this.match(SmartRuleParser.FROM);
			this.state = 86;
			this.timepointexpr(0);
			this.state = 89;
			this._errHandler.sync(this);
			_la = this._input.LA(1);
			if (_la===39) {
				{
				this.state = 87;
				this.match(SmartRuleParser.TO);
				this.state = 88;
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
		const localctx: ObjfilterContext = new ObjfilterContext(this, this._ctx, this.state);
		this.enterRule(localctx, 8, SmartRuleParser.RULE_objfilter);
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
	// @RuleVersion(0)
	public conditions(): ConditionsContext {
		const localctx: ConditionsContext = new ConditionsContext(this, this._ctx, this.state);
		this.enterRule(localctx, 10, SmartRuleParser.RULE_conditions);
		try {
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 93;
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

		const _parentctx: ParserRuleContext = this._ctx;
		const _parentState: number = this.state;
		let localctx: BoolvalueContext = new BoolvalueContext(this, this._ctx, _parentState);
		let _prevctx: BoolvalueContext = localctx;
		const _startState: number = 12;
		this.enterRecursionRule(localctx, 12, SmartRuleParser.RULE_boolvalue, _p);
		let _la: number;
		try {
			let _alt: number;
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 104;
			this._errHandler.sync(this);
			switch ( this._interp.adaptivePredict(this._input, 10, this._ctx) ) {
			case 1:
				{
				localctx = new BvCompareexprContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;

				this.state = 96;
				this.compareexpr();
				}
				break;
			case 2:
				{
				localctx = new BvNotContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 97;
				this.match(SmartRuleParser.NOT);
				this.state = 98;
				this.boolvalue(4);
				}
				break;
			case 3:
				{
				localctx = new BvIdContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 99;
				this.id();
				}
				break;
			case 4:
				{
				localctx = new BvCurveContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 100;
				this.match(SmartRuleParser.T__3);
				this.state = 101;
				this.boolvalue(0);
				this.state = 102;
				this.match(SmartRuleParser.T__4);
				}
				break;
			}
			this._ctx.stop = this._input.LT(-1);
			this.state = 111;
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
					this.state = 106;
					if (!(this.precpred(this._ctx, 3))) {
						throw this.createFailedPredicateException('this.precpred(this._ctx, 3)');
					}
					this.state = 107;
					_la = this._input.LA(1);
					if(!(_la===31 || _la===36)) {
					this._errHandler.recoverInline(this);
					}
					else {
						this._errHandler.reportMatch(this);
					    this.consume();
					}
					this.state = 108;
					this.boolvalue(4);
					}
					}
				}
				this.state = 113;
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
		let _la: number;
		try {
			this.state = 134;
			this._errHandler.sync(this);
			switch ( this._interp.adaptivePredict(this._input, 12, this._ctx) ) {
			case 1:
				localctx = new CmpIdLongContext(this, localctx);
				this.enterOuterAlt(localctx, 1);
				{
				this.state = 114;
				this.numricexpr(0);
				this.state = 115;
				this.oPCMP();
				this.state = 116;
				this.numricexpr(0);
				}
				break;
			case 2:
				localctx = new CmpIdStringContext(this, localctx);
				this.enterOuterAlt(localctx, 2);
				{
				this.state = 118;
				this.stringexpr(0);
				this.state = 119;
				_la = this._input.LA(1);
				if(!(_la===6 || _la===7)) {
				this._errHandler.recoverInline(this);
				}
				else {
					this._errHandler.reportMatch(this);
				    this.consume();
				}
				this.state = 120;
				this.stringexpr(0);
				}
				break;
			case 3:
				localctx = new CmpIdStringMatchesContext(this, localctx);
				this.enterOuterAlt(localctx, 3);
				{
				this.state = 122;
				this.stringexpr(0);
				this.state = 123;
				this.match(SmartRuleParser.MATCHES);
				this.state = 124;
				this.stringexpr(0);
				}
				break;
			case 4:
				localctx = new CmpTimeintvalTimeintvalContext(this, localctx);
				this.enterOuterAlt(localctx, 4);
				{
				this.state = 126;
				this.timeintvalexpr(0);
				this.state = 127;
				this.oPCMP();
				this.state = 128;
				this.timeintvalexpr(0);
				}
				break;
			case 5:
				localctx = new CmpTimepointTimePointContext(this, localctx);
				this.enterOuterAlt(localctx, 5);
				{
				this.state = 130;
				this.timepointexpr(0);
				this.state = 131;
				this.oPCMP();
				this.state = 132;
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

		const _parentctx: ParserRuleContext = this._ctx;
		const _parentState: number = this.state;
		let localctx: TimeintvalexprContext = new TimeintvalexprContext(this, this._ctx, _parentState);
		let _prevctx: TimeintvalexprContext = localctx;
		const _startState: number = 16;
		this.enterRecursionRule(localctx, 16, SmartRuleParser.RULE_timeintvalexpr, _p);
		let _la: number;
		try {
			let _alt: number;
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 147;
			this._errHandler.sync(this);
			switch ( this._interp.adaptivePredict(this._input, 13, this._ctx) ) {
			case 1:
				{
				localctx = new TieCurvesContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;

				this.state = 137;
				this.match(SmartRuleParser.T__3);
				this.state = 138;
				this.timeintvalexpr(0);
				this.state = 139;
				this.match(SmartRuleParser.T__4);
				}
				break;
			case 2:
				{
				localctx = new TieConstContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 141;
				this.match(SmartRuleParser.TIMEINTVALCONST);
				}
				break;
			case 3:
				{
				localctx = new TieTpExprContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 142;
				this.timepointexpr(0);
				this.state = 143;
				this.match(SmartRuleParser.T__7);
				this.state = 144;
				this.timepointexpr(0);
				}
				break;
			case 4:
				{
				localctx = new TieTiIdExprContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 146;
				this.id();
				}
				break;
			}
			this._ctx.stop = this._input.LT(-1);
			this.state = 154;
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
					this.state = 149;
					if (!(this.precpred(this._ctx, 2))) {
						throw this.createFailedPredicateException('this.precpred(this._ctx, 2)');
					}
					this.state = 150;
					_la = this._input.LA(1);
					if(!(_la===8 || _la===9)) {
					this._errHandler.recoverInline(this);
					}
					else {
						this._errHandler.reportMatch(this);
					    this.consume();
					}
					this.state = 151;
					this.timeintvalexpr(3);
					}
					}
				}
				this.state = 156;
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

		const _parentctx: ParserRuleContext = this._ctx;
		const _parentState: number = this.state;
		let localctx: TimepointexprContext = new TimepointexprContext(this, this._ctx, _parentState);
		let _prevctx: TimepointexprContext = localctx;
		const _startState: number = 18;
		this.enterRecursionRule(localctx, 18, SmartRuleParser.RULE_timepointexpr, _p);
		let _la: number;
		try {
			let _alt: number;
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 165;
			this._errHandler.sync(this);
			switch (this._input.LA(1)) {
			case 4:
				{
				localctx = new TpeCurvesContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;

				this.state = 158;
				this.match(SmartRuleParser.T__3);
				this.state = 159;
				this.timepointexpr(0);
				this.state = 160;
				this.match(SmartRuleParser.T__4);
				}
				break;
			case 37:
				{
				localctx = new TpeNowContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 162;
				this.match(SmartRuleParser.NOW);
				}
				break;
			case 50:
				{
				localctx = new TpeTimeConstContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 163;
				this.match(SmartRuleParser.TIMEPOINTCONST);
				}
				break;
			case 29:
			case 51:
				{
				localctx = new TpeTimeIdContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 164;
				this.id();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
			this._ctx.stop = this._input.LT(-1);
			this.state = 172;
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
					this.state = 167;
					if (!(this.precpred(this._ctx, 2))) {
						throw this.createFailedPredicateException('this.precpred(this._ctx, 2)');
					}
					this.state = 168;
					_la = this._input.LA(1);
					if(!(_la===8 || _la===9)) {
					this._errHandler.recoverInline(this);
					}
					else {
						this._errHandler.reportMatch(this);
					    this.consume();
					}
					this.state = 169;
					this.timeintvalexpr(0);
					}
					}
				}
				this.state = 174;
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
		const localctx: CommonexprContext = new CommonexprContext(this, this._ctx, this.state);
		this.enterRule(localctx, 20, SmartRuleParser.RULE_commonexpr);
		try {
			this.state = 186;
			this._errHandler.sync(this);
			switch ( this._interp.adaptivePredict(this._input, 17, this._ctx) ) {
			case 1:
				this.enterOuterAlt(localctx, 1);
				{
				this.state = 175;
				this.boolvalue(0);
				}
				break;
			case 2:
				this.enterOuterAlt(localctx, 2);
				{
				this.state = 176;
				this.timeintvalexpr(0);
				}
				break;
			case 3:
				this.enterOuterAlt(localctx, 3);
				{
				this.state = 177;
				this.timepointexpr(0);
				}
				break;
			case 4:
				this.enterOuterAlt(localctx, 4);
				{
				this.state = 178;
				this.numricexpr(0);
				}
				break;
			case 5:
				this.enterOuterAlt(localctx, 5);
				{
				this.state = 179;
				this.match(SmartRuleParser.LONG);
				}
				break;
			case 6:
				this.enterOuterAlt(localctx, 6);
				{
				this.state = 180;
				this.match(SmartRuleParser.STRING);
				}
				break;
			case 7:
				this.enterOuterAlt(localctx, 7);
				{
				this.state = 181;
				this.id();
				}
				break;
			case 8:
				this.enterOuterAlt(localctx, 8);
				{
				this.state = 182;
				this.match(SmartRuleParser.T__3);
				this.state = 183;
				this.commonexpr();
				this.state = 184;
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

		const _parentctx: ParserRuleContext = this._ctx;
		const _parentState: number = this.state;
		let localctx: NumricexprContext = new NumricexprContext(this, this._ctx, _parentState);
		let _prevctx: NumricexprContext = localctx;
		const _startState: number = 22;
		this.enterRecursionRule(localctx, 22, SmartRuleParser.RULE_numricexpr, _p);
		let _la: number;
		try {
			let _alt: number;
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 195;
			this._errHandler.sync(this);
			switch (this._input.LA(1)) {
			case 29:
			case 51:
				{
				localctx = new NumricexprIdContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;

				this.state = 189;
				this.id();
				}
				break;
			case 55:
				{
				localctx = new NumricexprLongContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 190;
				this.match(SmartRuleParser.LONG);
				}
				break;
			case 4:
				{
				localctx = new NumricexprCurveContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 191;
				this.match(SmartRuleParser.T__3);
				this.state = 192;
				this.numricexpr(0);
				this.state = 193;
				this.match(SmartRuleParser.T__4);
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
			this._ctx.stop = this._input.LT(-1);
			this.state = 205;
			this._errHandler.sync(this);
			_alt = this._interp.adaptivePredict(this._input, 20, this._ctx);
			while (_alt !== 2 && _alt !== ATN.INVALID_ALT_NUMBER) {
				if (_alt === 1) {
					if (this._parseListeners != null) {
						this.triggerExitRuleEvent();
					}
					_prevctx = localctx;
					{
					this.state = 203;
					this._errHandler.sync(this);
					switch ( this._interp.adaptivePredict(this._input, 19, this._ctx) ) {
					case 1:
						{
						localctx = new NumricexprMulContext(this, new NumricexprContext(this, _parentctx, _parentState));
						this.pushNewRecursionContext(localctx, _startState, SmartRuleParser.RULE_numricexpr);
						this.state = 197;
						if (!(this.precpred(this._ctx, 5))) {
							throw this.createFailedPredicateException('this.precpred(this._ctx, 5)');
						}
						this.state = 198;
						(localctx as NumricexprMulContext)._op = this._input.LT(1);
						_la = this._input.LA(1);
						if(!((((_la) & ~0x1F) === 0 && ((1 << _la) & 3080) !== 0))) {
						    (localctx as NumricexprMulContext)._op = this._errHandler.recoverInline(this);
						}
						else {
							this._errHandler.reportMatch(this);
						    this.consume();
						}
						this.state = 199;
						this.numricexpr(6);
						}
						break;
					case 2:
						{
						localctx = new NumricexprAddContext(this, new NumricexprContext(this, _parentctx, _parentState));
						this.pushNewRecursionContext(localctx, _startState, SmartRuleParser.RULE_numricexpr);
						this.state = 200;
						if (!(this.precpred(this._ctx, 4))) {
							throw this.createFailedPredicateException('this.precpred(this._ctx, 4)');
						}
						this.state = 201;
						(localctx as NumricexprAddContext)._op = this._input.LT(1);
						_la = this._input.LA(1);
						if(!(_la===8 || _la===9)) {
						    (localctx as NumricexprAddContext)._op = this._errHandler.recoverInline(this);
						}
						else {
							this._errHandler.reportMatch(this);
						    this.consume();
						}
						this.state = 202;
						this.numricexpr(5);
						}
						break;
					}
					}
				}
				this.state = 207;
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

		const _parentctx: ParserRuleContext = this._ctx;
		const _parentState: number = this.state;
		let localctx: StringexprContext = new StringexprContext(this, this._ctx, _parentState);
		let _prevctx: StringexprContext = localctx;
		const _startState: number = 24;
		this.enterRecursionRule(localctx, 24, SmartRuleParser.RULE_stringexpr, _p);
		try {
			let _alt: number;
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 216;
			this._errHandler.sync(this);
			switch (this._input.LA(1)) {
			case 4:
				{
				localctx = new StrCurveContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;

				this.state = 209;
				this.match(SmartRuleParser.T__3);
				this.state = 210;
				this.stringexpr(0);
				this.state = 211;
				this.match(SmartRuleParser.T__4);
				}
				break;
			case 54:
				{
				localctx = new StrOrdStringContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 213;
				this.match(SmartRuleParser.STRING);
				}
				break;
			case 50:
				{
				localctx = new StrTimePointStrContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 214;
				this.match(SmartRuleParser.TIMEPOINTCONST);
				}
				break;
			case 29:
			case 51:
				{
				localctx = new StrIDContext(this, localctx);
				this._ctx = localctx;
				_prevctx = localctx;
				this.state = 215;
				this.id();
				}
				break;
			default:
				throw new NoViableAltException(this);
			}
			this._ctx.stop = this._input.LT(-1);
			this.state = 223;
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
					this.state = 218;
					if (!(this.precpred(this._ctx, 1))) {
						throw this.createFailedPredicateException('this.precpred(this._ctx, 1)');
					}
					this.state = 219;
					this.match(SmartRuleParser.T__8);
					this.state = 220;
					this.stringexpr(2);
					}
					}
				}
				this.state = 225;
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
		const localctx: CmdletContext = new CmdletContext(this, this._ctx, this.state);
		this.enterRule(localctx, 26, SmartRuleParser.RULE_cmdlet);
		let _la: number;
		try {
			this.state = 243;
			this._errHandler.sync(this);
			switch ( this._interp.adaptivePredict(this._input, 24, this._ctx) ) {
			case 1:
				this.enterOuterAlt(localctx, 1);
				{
				this.state = 229;
				this._errHandler.sync(this);
				_la = this._input.LA(1);
				while ((((_la) & ~0x1F) === 0 && ((1 << _la) & 4294967294) !== 0) || ((((_la - 32)) & ~0x1F) === 0 && ((1 << (_la - 32)) & 33554431) !== 0)) {
					{
					{
					this.state = 226;
					this.matchWildcard();
					}
					}
					this.state = 231;
					this._errHandler.sync(this);
					_la = this._input.LA(1);
				}
				}
				break;
			case 2:
				this.enterOuterAlt(localctx, 2);
				{
				this.state = 232;
				this.match(SmartRuleParser.T__11);
				}
				break;
			case 3:
				this.enterOuterAlt(localctx, 3);
				{
				this.state = 233;
				this.match(SmartRuleParser.T__12);
				}
				break;
			case 4:
				this.enterOuterAlt(localctx, 4);
				{
				this.state = 234;
				this.match(SmartRuleParser.T__13);
				}
				break;
			case 5:
				this.enterOuterAlt(localctx, 5);
				{
				this.state = 235;
				this.match(SmartRuleParser.T__14);
				}
				break;
			case 6:
				this.enterOuterAlt(localctx, 6);
				{
				this.state = 236;
				this.match(SmartRuleParser.T__15);
				}
				break;
			case 7:
				this.enterOuterAlt(localctx, 7);
				{
				this.state = 237;
				this.match(SmartRuleParser.T__16);
				}
				break;
			case 8:
				this.enterOuterAlt(localctx, 8);
				{
				this.state = 238;
				this.match(SmartRuleParser.T__17);
				}
				break;
			case 9:
				this.enterOuterAlt(localctx, 9);
				{
				this.state = 239;
				this.match(SmartRuleParser.T__18);
				}
				break;
			case 10:
				this.enterOuterAlt(localctx, 10);
				{
				this.state = 240;
				this.match(SmartRuleParser.T__19);
				}
				break;
			case 11:
				this.enterOuterAlt(localctx, 11);
				{
				this.state = 241;
				this.match(SmartRuleParser.T__20);
				}
				break;
			case 12:
				this.enterOuterAlt(localctx, 12);
				{
				this.state = 242;
				this.match(SmartRuleParser.T__21);
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
			this.state = 275;
			this._errHandler.sync(this);
			switch ( this._interp.adaptivePredict(this._input, 27, this._ctx) ) {
			case 1:
				localctx = new IdAttContext(this, localctx);
				this.enterOuterAlt(localctx, 1);
				{
				this.state = 245;
				this.match(SmartRuleParser.ID);
				}
				break;
			case 2:
				localctx = new IdObjAttContext(this, localctx);
				this.enterOuterAlt(localctx, 2);
				{
				this.state = 246;
				this.match(SmartRuleParser.OBJECTTYPE);
				this.state = 247;
				this.match(SmartRuleParser.T__22);
				this.state = 248;
				this.match(SmartRuleParser.ID);
				}
				break;
			case 3:
				localctx = new IdAttParaContext(this, localctx);
				this.enterOuterAlt(localctx, 3);
				{
				this.state = 249;
				this.match(SmartRuleParser.ID);
				this.state = 250;
				this.match(SmartRuleParser.T__3);
				this.state = 251;
				this.constexpr();
				this.state = 256;
				this._errHandler.sync(this);
				_la = this._input.LA(1);
				while (_la===24) {
					{
					{
					this.state = 252;
					this.match(SmartRuleParser.T__23);
					this.state = 253;
					this.constexpr();
					}
					}
					this.state = 258;
					this._errHandler.sync(this);
					_la = this._input.LA(1);
				}
				this.state = 259;
				this.match(SmartRuleParser.T__4);
				}
				break;
			case 4:
				localctx = new IdObjAttParaContext(this, localctx);
				this.enterOuterAlt(localctx, 4);
				{
				this.state = 261;
				this.match(SmartRuleParser.OBJECTTYPE);
				this.state = 262;
				this.match(SmartRuleParser.T__22);
				this.state = 263;
				this.match(SmartRuleParser.ID);
				this.state = 264;
				this.match(SmartRuleParser.T__3);
				this.state = 265;
				this.constexpr();
				this.state = 270;
				this._errHandler.sync(this);
				_la = this._input.LA(1);
				while (_la===24) {
					{
					{
					this.state = 266;
					this.match(SmartRuleParser.T__23);
					this.state = 267;
					this.constexpr();
					}
					}
					this.state = 272;
					this._errHandler.sync(this);
					_la = this._input.LA(1);
				}
				this.state = 273;
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
	public oPCMP(): OPCMPContext {
		const localctx: OPCMPContext = new OPCMPContext(this, this._ctx, this.state);
		this.enterRule(localctx, 30, SmartRuleParser.RULE_oPCMP);
		let _la: number;
		try {
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 277;
			_la = this._input.LA(1);
			if(!((((_la) & ~0x1F) === 0 && ((1 << _la) & 503316672) !== 0))) {
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
	public opr(): OprContext {
		const localctx: OprContext = new OprContext(this, this._ctx, this.state);
		this.enterRule(localctx, 32, SmartRuleParser.RULE_opr);
		let _la: number;
		try {
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 279;
			_la = this._input.LA(1);
			if(!((((_la) & ~0x1F) === 0 && ((1 << _la) & 3848) !== 0))) {
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
		const localctx: FileEventContext = new FileEventContext(this, this._ctx, this.state);
		this.enterRule(localctx, 34, SmartRuleParser.RULE_fileEvent);
		let _la: number;
		try {
			this.enterOuterAlt(localctx, 1);
			{
			this.state = 281;
			_la = this._input.LA(1);
			if(!(((((_la - 42)) & ~0x1F) === 0 && ((1 << (_la - 42)) & 127) !== 0))) {
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
		this.enterRule(localctx, 36, SmartRuleParser.RULE_constexpr);
		try {
			this.state = 287;
			this._errHandler.sync(this);
			switch (this._input.LA(1)) {
			case 55:
				localctx = new ConstLongContext(this, localctx);
				this.enterOuterAlt(localctx, 1);
				{
				this.state = 283;
				this.match(SmartRuleParser.LONG);
				}
				break;
			case 54:
				localctx = new ConstStringContext(this, localctx);
				this.enterOuterAlt(localctx, 2);
				{
				this.state = 284;
				this.match(SmartRuleParser.STRING);
				}
				break;
			case 49:
				localctx = new ConstTimeInvervalContext(this, localctx);
				this.enterOuterAlt(localctx, 3);
				{
				this.state = 285;
				this.match(SmartRuleParser.TIMEINTVALCONST);
				}
				break;
			case 50:
				localctx = new ConstTimePointContext(this, localctx);
				this.enterOuterAlt(localctx, 4);
				{
				this.state = 286;
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

	public static readonly _serializedATN: number[] = [4,1,56,290,2,0,7,0,2,
	1,7,1,2,2,7,2,2,3,7,3,2,4,7,4,2,5,7,5,2,6,7,6,2,7,7,7,2,8,7,8,2,9,7,9,2,
	10,7,10,2,11,7,11,2,12,7,12,2,13,7,13,2,14,7,14,2,15,7,15,2,16,7,16,2,17,
	7,17,2,18,7,18,1,0,1,0,1,0,1,0,1,0,3,0,44,8,0,1,0,1,0,1,0,1,0,1,0,4,0,51,
	8,0,11,0,12,0,52,3,0,55,8,0,1,1,1,1,1,1,1,1,3,1,61,8,1,1,2,1,2,1,2,1,2,
	1,2,1,2,1,2,1,2,3,2,71,8,2,3,2,73,8,2,1,2,3,2,76,8,2,1,2,1,2,1,2,3,2,81,
	8,2,1,2,3,2,84,8,2,1,3,1,3,1,3,1,3,3,3,90,8,3,1,4,1,4,1,5,1,5,1,6,1,6,1,
	6,1,6,1,6,1,6,1,6,1,6,1,6,3,6,105,8,6,1,6,1,6,1,6,5,6,110,8,6,10,6,12,6,
	113,9,6,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,1,7,
	1,7,1,7,1,7,1,7,3,7,135,8,7,1,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,
	3,8,148,8,8,1,8,1,8,1,8,5,8,153,8,8,10,8,12,8,156,9,8,1,9,1,9,1,9,1,9,1,
	9,1,9,1,9,1,9,3,9,166,8,9,1,9,1,9,1,9,5,9,171,8,9,10,9,12,9,174,9,9,1,10,
	1,10,1,10,1,10,1,10,1,10,1,10,1,10,1,10,1,10,1,10,3,10,187,8,10,1,11,1,
	11,1,11,1,11,1,11,1,11,1,11,3,11,196,8,11,1,11,1,11,1,11,1,11,1,11,1,11,
	5,11,204,8,11,10,11,12,11,207,9,11,1,12,1,12,1,12,1,12,1,12,1,12,1,12,1,
	12,3,12,217,8,12,1,12,1,12,1,12,5,12,222,8,12,10,12,12,12,225,9,12,1,13,
	5,13,228,8,13,10,13,12,13,231,9,13,1,13,1,13,1,13,1,13,1,13,1,13,1,13,1,
	13,1,13,1,13,1,13,3,13,244,8,13,1,14,1,14,1,14,1,14,1,14,1,14,1,14,1,14,
	1,14,5,14,255,8,14,10,14,12,14,258,9,14,1,14,1,14,1,14,1,14,1,14,1,14,1,
	14,1,14,1,14,5,14,269,8,14,10,14,12,14,272,9,14,1,14,1,14,3,14,276,8,14,
	1,15,1,15,1,16,1,16,1,17,1,17,1,18,1,18,1,18,1,18,3,18,288,8,18,1,18,0,
	5,12,16,18,22,24,19,0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,
	0,7,2,0,31,31,36,36,1,0,6,7,1,0,8,9,2,0,3,3,10,11,2,0,6,7,25,28,2,0,3,3,
	8,11,1,0,42,48,333,0,54,1,0,0,0,2,60,1,0,0,0,4,83,1,0,0,0,6,85,1,0,0,0,
	8,91,1,0,0,0,10,93,1,0,0,0,12,104,1,0,0,0,14,134,1,0,0,0,16,147,1,0,0,0,
	18,165,1,0,0,0,20,186,1,0,0,0,22,195,1,0,0,0,24,216,1,0,0,0,26,243,1,0,
	0,0,28,275,1,0,0,0,30,277,1,0,0,0,32,279,1,0,0,0,34,281,1,0,0,0,36,287,
	1,0,0,0,38,39,3,2,1,0,39,43,5,1,0,0,40,41,3,4,2,0,41,42,5,2,0,0,42,44,1,
	0,0,0,43,40,1,0,0,0,43,44,1,0,0,0,44,45,1,0,0,0,45,46,3,10,5,0,46,47,5,
	2,0,0,47,48,3,26,13,0,48,55,1,0,0,0,49,51,5,52,0,0,50,49,1,0,0,0,51,52,
	1,0,0,0,52,50,1,0,0,0,52,53,1,0,0,0,53,55,1,0,0,0,54,38,1,0,0,0,54,50,1,
	0,0,0,55,1,1,0,0,0,56,61,5,29,0,0,57,58,5,29,0,0,58,59,5,40,0,0,59,61,3,
	8,4,0,60,56,1,0,0,0,60,57,1,0,0,0,61,3,1,0,0,0,62,63,5,30,0,0,63,84,3,18,
	9,0,64,65,5,32,0,0,65,72,3,16,8,0,66,67,5,3,0,0,67,70,3,16,8,0,68,69,5,
	3,0,0,69,71,3,16,8,0,70,68,1,0,0,0,70,71,1,0,0,0,71,73,1,0,0,0,72,66,1,
	0,0,0,72,73,1,0,0,0,73,75,1,0,0,0,74,76,3,6,3,0,75,74,1,0,0,0,75,76,1,0,
	0,0,76,84,1,0,0,0,77,78,5,34,0,0,78,80,3,34,17,0,79,81,3,6,3,0,80,79,1,
	0,0,0,80,81,1,0,0,0,81,84,1,0,0,0,82,84,5,35,0,0,83,62,1,0,0,0,83,64,1,
	0,0,0,83,77,1,0,0,0,83,82,1,0,0,0,84,5,1,0,0,0,85,86,5,33,0,0,86,89,3,18,
	9,0,87,88,5,39,0,0,88,90,3,18,9,0,89,87,1,0,0,0,89,90,1,0,0,0,90,7,1,0,
	0,0,91,92,3,12,6,0,92,9,1,0,0,0,93,94,3,12,6,0,94,11,1,0,0,0,95,96,6,6,
	-1,0,96,105,3,14,7,0,97,98,5,38,0,0,98,105,3,12,6,4,99,105,3,28,14,0,100,
	101,5,4,0,0,101,102,3,12,6,0,102,103,5,5,0,0,103,105,1,0,0,0,104,95,1,0,
	0,0,104,97,1,0,0,0,104,99,1,0,0,0,104,100,1,0,0,0,105,111,1,0,0,0,106,107,
	10,3,0,0,107,108,7,0,0,0,108,110,3,12,6,4,109,106,1,0,0,0,110,113,1,0,0,
	0,111,109,1,0,0,0,111,112,1,0,0,0,112,13,1,0,0,0,113,111,1,0,0,0,114,115,
	3,22,11,0,115,116,3,30,15,0,116,117,3,22,11,0,117,135,1,0,0,0,118,119,3,
	24,12,0,119,120,7,1,0,0,120,121,3,24,12,0,121,135,1,0,0,0,122,123,3,24,
	12,0,123,124,5,41,0,0,124,125,3,24,12,0,125,135,1,0,0,0,126,127,3,16,8,
	0,127,128,3,30,15,0,128,129,3,16,8,0,129,135,1,0,0,0,130,131,3,18,9,0,131,
	132,3,30,15,0,132,133,3,18,9,0,133,135,1,0,0,0,134,114,1,0,0,0,134,118,
	1,0,0,0,134,122,1,0,0,0,134,126,1,0,0,0,134,130,1,0,0,0,135,15,1,0,0,0,
	136,137,6,8,-1,0,137,138,5,4,0,0,138,139,3,16,8,0,139,140,5,5,0,0,140,148,
	1,0,0,0,141,148,5,49,0,0,142,143,3,18,9,0,143,144,5,8,0,0,144,145,3,18,
	9,0,145,148,1,0,0,0,146,148,3,28,14,0,147,136,1,0,0,0,147,141,1,0,0,0,147,
	142,1,0,0,0,147,146,1,0,0,0,148,154,1,0,0,0,149,150,10,2,0,0,150,151,7,
	2,0,0,151,153,3,16,8,3,152,149,1,0,0,0,153,156,1,0,0,0,154,152,1,0,0,0,
	154,155,1,0,0,0,155,17,1,0,0,0,156,154,1,0,0,0,157,158,6,9,-1,0,158,159,
	5,4,0,0,159,160,3,18,9,0,160,161,5,5,0,0,161,166,1,0,0,0,162,166,5,37,0,
	0,163,166,5,50,0,0,164,166,3,28,14,0,165,157,1,0,0,0,165,162,1,0,0,0,165,
	163,1,0,0,0,165,164,1,0,0,0,166,172,1,0,0,0,167,168,10,2,0,0,168,169,7,
	2,0,0,169,171,3,16,8,0,170,167,1,0,0,0,171,174,1,0,0,0,172,170,1,0,0,0,
	172,173,1,0,0,0,173,19,1,0,0,0,174,172,1,0,0,0,175,187,3,12,6,0,176,187,
	3,16,8,0,177,187,3,18,9,0,178,187,3,22,11,0,179,187,5,55,0,0,180,187,5,
	54,0,0,181,187,3,28,14,0,182,183,5,4,0,0,183,184,3,20,10,0,184,185,5,5,
	0,0,185,187,1,0,0,0,186,175,1,0,0,0,186,176,1,0,0,0,186,177,1,0,0,0,186,
	178,1,0,0,0,186,179,1,0,0,0,186,180,1,0,0,0,186,181,1,0,0,0,186,182,1,0,
	0,0,187,21,1,0,0,0,188,189,6,11,-1,0,189,196,3,28,14,0,190,196,5,55,0,0,
	191,192,5,4,0,0,192,193,3,22,11,0,193,194,5,5,0,0,194,196,1,0,0,0,195,188,
	1,0,0,0,195,190,1,0,0,0,195,191,1,0,0,0,196,205,1,0,0,0,197,198,10,5,0,
	0,198,199,7,3,0,0,199,204,3,22,11,6,200,201,10,4,0,0,201,202,7,2,0,0,202,
	204,3,22,11,5,203,197,1,0,0,0,203,200,1,0,0,0,204,207,1,0,0,0,205,203,1,
	0,0,0,205,206,1,0,0,0,206,23,1,0,0,0,207,205,1,0,0,0,208,209,6,12,-1,0,
	209,210,5,4,0,0,210,211,3,24,12,0,211,212,5,5,0,0,212,217,1,0,0,0,213,217,
	5,54,0,0,214,217,5,50,0,0,215,217,3,28,14,0,216,208,1,0,0,0,216,213,1,0,
	0,0,216,214,1,0,0,0,216,215,1,0,0,0,217,223,1,0,0,0,218,219,10,1,0,0,219,
	220,5,9,0,0,220,222,3,24,12,2,221,218,1,0,0,0,222,225,1,0,0,0,223,221,1,
	0,0,0,223,224,1,0,0,0,224,25,1,0,0,0,225,223,1,0,0,0,226,228,9,0,0,0,227,
	226,1,0,0,0,228,231,1,0,0,0,229,227,1,0,0,0,229,230,1,0,0,0,230,244,1,0,
	0,0,231,229,1,0,0,0,232,244,5,12,0,0,233,244,5,13,0,0,234,244,5,14,0,0,
	235,244,5,15,0,0,236,244,5,16,0,0,237,244,5,17,0,0,238,244,5,18,0,0,239,
	244,5,19,0,0,240,244,5,20,0,0,241,244,5,21,0,0,242,244,5,22,0,0,243,229,
	1,0,0,0,243,232,1,0,0,0,243,233,1,0,0,0,243,234,1,0,0,0,243,235,1,0,0,0,
	243,236,1,0,0,0,243,237,1,0,0,0,243,238,1,0,0,0,243,239,1,0,0,0,243,240,
	1,0,0,0,243,241,1,0,0,0,243,242,1,0,0,0,244,27,1,0,0,0,245,276,5,51,0,0,
	246,247,5,29,0,0,247,248,5,23,0,0,248,276,5,51,0,0,249,250,5,51,0,0,250,
	251,5,4,0,0,251,256,3,36,18,0,252,253,5,24,0,0,253,255,3,36,18,0,254,252,
	1,0,0,0,255,258,1,0,0,0,256,254,1,0,0,0,256,257,1,0,0,0,257,259,1,0,0,0,
	258,256,1,0,0,0,259,260,5,5,0,0,260,276,1,0,0,0,261,262,5,29,0,0,262,263,
	5,23,0,0,263,264,5,51,0,0,264,265,5,4,0,0,265,270,3,36,18,0,266,267,5,24,
	0,0,267,269,3,36,18,0,268,266,1,0,0,0,269,272,1,0,0,0,270,268,1,0,0,0,270,
	271,1,0,0,0,271,273,1,0,0,0,272,270,1,0,0,0,273,274,5,5,0,0,274,276,1,0,
	0,0,275,245,1,0,0,0,275,246,1,0,0,0,275,249,1,0,0,0,275,261,1,0,0,0,276,
	29,1,0,0,0,277,278,7,4,0,0,278,31,1,0,0,0,279,280,7,5,0,0,280,33,1,0,0,
	0,281,282,7,6,0,0,282,35,1,0,0,0,283,288,5,55,0,0,284,288,5,54,0,0,285,
	288,5,49,0,0,286,288,5,50,0,0,287,283,1,0,0,0,287,284,1,0,0,0,287,285,1,
	0,0,0,287,286,1,0,0,0,288,37,1,0,0,0,29,43,52,54,60,70,72,75,80,83,89,104,
	111,134,147,154,165,172,186,195,203,205,216,223,229,243,256,270,275,287];

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
	public oPCMP(): OPCMPContext {
		return this.getTypedRuleContext(OPCMPContext, 0) as OPCMPContext;
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
	public oPCMP(): OPCMPContext {
		return this.getTypedRuleContext(OPCMPContext, 0) as OPCMPContext;
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
	public oPCMP(): OPCMPContext {
		return this.getTypedRuleContext(OPCMPContext, 0) as OPCMPContext;
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


export class OPCMPContext extends ParserRuleContext {
	constructor(parser?: SmartRuleParser, parent?: ParserRuleContext, invokingState?: number) {
		super(parent, invokingState);
    	this.parser = parser;
	}
    public get ruleIndex(): number {
    	return SmartRuleParser.RULE_oPCMP;
	}
	public enterRule(listener: SmartRuleListener): void {
	    if(listener.enterOPCMP) {
	 		listener.enterOPCMP(this);
		}
	}
	public exitRule(listener: SmartRuleListener): void {
	    if(listener.exitOPCMP) {
	 		listener.exitOPCMP(this);
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
