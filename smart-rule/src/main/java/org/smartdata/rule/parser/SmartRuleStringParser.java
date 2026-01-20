/**
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
package org.smartdata.rule.parser;

import com.google.common.collect.ImmutableMap;
import org.antlr.v4.runtime.ANTLRInputStream;
import org.antlr.v4.runtime.BaseErrorListener;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.Parser;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.runtime.Recognizer;
import org.antlr.v4.runtime.tree.ParseTree;
import org.smartdata.SmartConstants;
import org.smartdata.conf.SmartConf;
import org.smartdata.exception.SsmParseException;
import org.smartdata.model.CmdletDescriptor;
import org.smartdata.model.rule.RuleTranslationResult;
import org.smartdata.rule.objects.SmartObjectSupplier;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/** Parser a rule string and translate it. */
public class SmartRuleStringParser {
  private static final Map<String, String> CONDITION_REWRITES =
      ImmutableMap.<String, String>builder()
          .put("allssd", "storagePolicy != \"ALL_SSD\"")
          .put("onessd", "storagePolicy != \"ONE_SSD\"")
          .put("archive", "storagePolicy != \"COLD\"")
          .put("alldisk", "storagePolicy != \"HOT\"")
          .put("onedisk", "storagePolicy != \"WARM\"")
          .put("ramdisk", "storagePolicy != \"LAZY_PERSIST\"")
          .put("cache", "not inCache")
          .put("uncache", "inCache")
          .put("sync", "unsynced")
          .put("ec", "1")
          .put("unec", "1")
          .build();


  private final String rule;
  private final SmartConf conf;
  private final TranslationContext ctx;
  private final SmartObjectSupplier smartObjectSupplier;
  private final List<RecognitionException> parseErrors = new ArrayList<>();

  private String parserErrorMessage = "";

  public SmartRuleStringParser(String rule, TranslationContext ctx,
      SmartObjectSupplier smartObjectSupplier, SmartConf conf) {
    this.rule = rule;
    this.ctx = ctx;
    this.conf = conf;
    this.smartObjectSupplier = smartObjectSupplier;
  }

  public RuleTranslationResult translate() throws IOException {
    RuleTranslationResult tr = doTranslate(rule);
    CmdletDescriptor cmdDes = tr.getCmdDescriptor();
    if (cmdDes.getActionSize() == 0) {
      throw new IOException("No cmdlet specified in Rule");
    }
    String actName = cmdDes.getActionName(0);
    if (cmdDes.getActionSize() != 1 || CONDITION_REWRITES.get(actName) == null) {
      return tr;
    }

    String repl = CONDITION_REWRITES.get(actName);
    if (cmdDes.getActionName(0).equals("ec") || cmdDes.getActionName(0).equals("unec")) {
      String policy;
      if (cmdDes.getActionName(0).equals("ec")) {
        policy = cmdDes.getActionArgs(0).get("-policy");
        if (policy == null) {
          policy = conf.getTrimmed("dfs.namenode.ec.system.default.policy",
              "RS-6-3-1024k");
        }
      } else {
        policy = SmartConstants.REPLICATION_CODEC_NAME;
      }
      repl = "ecPolicy != \"" + policy + "\"";
    }
    int[] condPosition = tr.getCondPosition();
    String cond = rule.substring(condPosition[0], condPosition[1] + 1);
    String optRule = rule.replace(cond, repl + " and (" + cond + ")");
    return doTranslate(optRule);
  }

  private RuleTranslationResult doTranslate(String rule) throws IOException {
    parseErrors.clear();
    parserErrorMessage = "";

    InputStream input = new ByteArrayInputStream(rule.getBytes());
    ANTLRInputStream antlrInput = new ANTLRInputStream(input);
    SmartRuleLexer lexer = new SmartRuleLexer(antlrInput);
    CommonTokenStream tokens = new CommonTokenStream(lexer);
    SmartRuleParser parser = new SmartRuleParser(tokens);
    parser.removeErrorListeners();
    parser.addErrorListener(new SSMRuleErrorListener());
    ParseTree tree = parser.ssmrule();

    if (!parseErrors.isEmpty()) {
      throw new SsmParseException(parserErrorMessage);
    }

    SmartRuleVisitTranslator visitor = new SmartRuleVisitTranslator(ctx, smartObjectSupplier);
    try {
      visitor.visit(tree);
    } catch (RuntimeException e) {
      throw new SsmParseException(e.getMessage(), e);
    }

    return visitor.generateSql();
  }

  public class SSMRuleErrorListener extends BaseErrorListener {
    @Override
    public void syntaxError(
        Recognizer<?, ?> recognizer,
        Object offendingSymbol,
        int line,
        int charPositionInLine,
        String msg,
        RecognitionException e) {
      List<String> stack = ((Parser) recognizer).getRuleInvocationStack();
      Collections.reverse(stack);
      parserErrorMessage += "Line " + line + ", Char " + charPositionInLine + " : " + msg + "\n";
      parseErrors.add(e);
    }
  }
}

