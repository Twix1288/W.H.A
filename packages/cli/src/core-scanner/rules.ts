import type { SyntaxNode, Tree } from 'tree-sitter';
import type Parser from 'tree-sitter';
import { ParseResult } from './parser';

export type FixStrategy = 'param_rewrite' | 'literal_stub';

export interface ASTQuery {
  type: 'ast';
  language: 'python' | 'javascript' | 'typescript' | 'bash' | 'rust';
  query: string;
}

export interface RegexQuery {
  type: 'regex';
  pattern: RegExp;
  context?: 'any_string_literal' | 'any';
}

export interface TextQuery {
  type: 'text';
  pattern: RegExp;
}

export interface Rule {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: 'prompt-injection' | 'dangerous-exec' | 'credential-exposure' | 'tool-poisoning';
  match: ASTQuery | RegexQuery | TextQuery;
  fixable: boolean;
  fixStrategy?: FixStrategy;
}

export interface Finding {
  ruleId: string;
  name: string;
  severity: string;
  category: string;
  message: string;
  node?: SyntaxNode;
  startIndex?: number;
  endIndex?: number;
  line: number;
  fixable: boolean;
  fixStrategy?: FixStrategy;
}

export const RULES: Rule[] = [
  {
    id: 'WHAgent-EXEC-001',
    name: 'Python subprocess shell=True Execution (Strict)',
    severity: 'critical',
    category: 'dangerous-exec',
    match: {
      type: 'ast',
      language: 'python',
      query: `
(call
  function: (attribute
    object: (identifier) @obj (#eq? @obj "subprocess")
    attribute: (identifier) @fn (#match? @fn "^(Popen|call|run)$"))
  arguments: (argument_list
    (keyword_argument
      name: (identifier) @kw (#eq? @kw "shell")
      value: (true) @val))) @call_expr
      `
    },
    fixable: true,
    fixStrategy: 'param_rewrite'
  },
  {
    id: 'WHAgent-EXEC-001b',
    name: 'Python shell=True Execution (Broad)',
    severity: 'critical',
    category: 'dangerous-exec',
    match: {
      type: 'ast',
      language: 'python',
      query: `
(call
  arguments: (argument_list
    (keyword_argument
      name: (identifier) @kw (#eq? @kw "shell")
      value: (true) @val))) @call_expr
      `
    },
    fixable: true,
    fixStrategy: 'param_rewrite'
  },
  {
    id: 'WHAgent-EXEC-002',
    name: 'JavaScript Eval Execution',
    severity: 'critical',
    category: 'dangerous-exec',
    match: {
      type: 'ast',
      language: 'javascript',
      query: `
(call_expression
  function: (identifier) @fn (#eq? @fn "eval")
  arguments: (arguments) @args) @eval_expr
      `
    },
    fixable: false
  },
  {
    id: 'WHAgent-EXEC-003',
    name: 'Bash Curl/Wget to Shell',
    severity: 'critical',
    category: 'dangerous-exec',
    match: {
      type: 'ast',
      language: 'bash',
      query: `
(pipeline
  (command
    name: (command_name) @cmd_fetch (#match? @cmd_fetch "^(curl|wget)$"))
  (command
    name: (command_name) @cmd_exec (#match? @cmd_exec "^(bash|sh|zsh)$"))) @pipeline_expr
      `
    },
    fixable: false
  },
  {
    id: 'WHAgent-CRED-001',
    name: 'Hardcoded API Key',
    severity: 'high',
    category: 'credential-exposure',
    match: {
      type: 'regex',
      pattern: /(sk-[a-zA-Z0-9-]{10,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16})/,
      context: 'any_string_literal'
    },
    fixable: true,
    fixStrategy: 'literal_stub'
  },
  {
    id: 'WHAgent-PI-001',
    name: 'Prompt Injection Pattern',
    severity: 'medium',
    category: 'prompt-injection',
    match: {
      type: 'regex',
      pattern: /(ignore|disregard|forget)\s+(all\s+)?(previous|prior)\s+instructions?/i,
      context: 'any_string_literal'
    },
    fixable: false
  }
];

export function runRules(parseResult: ParseResult, rules: Rule[]): Finding[] {
  const findings: Finding[] = [];

  if (parseResult.type === 'ast') {
    const { tree, parser } = parseResult;
    const language = parser.getLanguage();

    for (const rule of rules) {
      if (rule.match.type === 'ast') {
        try {
          const Query = require('tree-sitter').Query;
          if (Query && language) {
            const query = new Query(language, rule.match.query);
            const matches = query.matches(tree.rootNode);
            
            for (const match of matches) {
              const mainNode = match.captures[match.captures.length - 1].node;
              let targetNode = mainNode;
              if (rule.fixStrategy === 'param_rewrite') {
                const valCapture = match.captures.find((c: any) => c.name === 'val');
                if (valCapture) targetNode = valCapture.node;
              }

              findings.push({
                ruleId: rule.id,
                name: rule.name,
                severity: rule.severity,
                category: rule.category,
                message: `Matched AST pattern for ${rule.name}`,
                node: targetNode,
                startIndex: targetNode.startIndex,
                endIndex: targetNode.endIndex,
                line: targetNode.startPosition.row + 1,
                fixable: rule.fixable,
                fixStrategy: rule.fixStrategy
              });
            }
          }
        } catch (e) {
        }
      } else if (rule.match.type === 'regex') {
        if (rule.match.context === 'any_string_literal') {
          const traverse = (node: SyntaxNode) => {
            if (node.type === 'string' || node.type === 'string_literal' || node.type === 'template_string') {
              if (rule.match.type === 'regex' && rule.match.pattern.test(node.text)) {
                findings.push({
                  ruleId: rule.id,
                  name: rule.name,
                  severity: rule.severity,
                  category: rule.category,
                  message: `Found ${rule.name} in string literal`,
                  node: node,
                  startIndex: node.startIndex,
                  endIndex: node.endIndex,
                  line: node.startPosition.row + 1,
                  fixable: rule.fixable,
                  fixStrategy: rule.fixStrategy
                });
              }
            }
            for (let i = 0; i < node.childCount; i++) {
              traverse(node.child(i)!);
            }
          };
          traverse(tree.rootNode);
        }
      }
    }
  } else if (parseResult.type === 'text') {
    const { lines } = parseResult;
    for (const rule of rules) {
      if (rule.match.type === 'text') {
        lines.forEach((lineText, idx) => {
          if (rule.match.type === 'text' && rule.match.pattern.test(lineText)) {
            findings.push({
              ruleId: rule.id,
              name: rule.name,
              severity: rule.severity,
              category: rule.category,
              message: `Matched text pattern for ${rule.name}`,
              line: idx + 1,
              fixable: false
            });
          }
        });
      } else if (rule.match.type === 'regex') {
        lines.forEach((lineText, idx) => {
           if (rule.match.type === 'regex' && rule.match.pattern.test(lineText)) {
            findings.push({
              ruleId: rule.id,
              name: rule.name,
              severity: rule.severity,
              category: rule.category,
              message: `Matched regex pattern for ${rule.name} (Text Mode)`,
              line: idx + 1,
              fixable: false 
            });
           }
        });
      }
    }
  }

  return findings;
}
