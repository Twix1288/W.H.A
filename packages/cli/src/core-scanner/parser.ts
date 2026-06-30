import Parser from 'tree-sitter';
import Python from 'tree-sitter-python';
import JavaScript from 'tree-sitter-javascript';
import TypeScript from 'tree-sitter-typescript';
import Bash from 'tree-sitter-bash';
import Rust from 'tree-sitter-rust';
import * as path from 'node:path';
import * as fs from 'node:fs/promises';

export type ParseResult =
  | { type: 'ast'; tree: Parser.Tree; source: string; parser: Parser }
  | { type: 'text'; lines: string[]; source: string };

export async function parseFile(filePath: string): Promise<ParseResult> {
  const ext = path.extname(filePath);
  const source = await fs.readFile(filePath, 'utf-8');

  const parser = new Parser();

  switch (ext) {
    case '.py':
      parser.setLanguage(Python as any);
      break;
    case '.js':
      parser.setLanguage(JavaScript as any);
      break;
    case '.ts':
    case '.tsx':
      // tree-sitter-typescript exports { typescript, tsx }
      parser.setLanguage(((TypeScript as any).typescript || TypeScript) as any);
      break;
    case '.sh':
    case '.bash':
      parser.setLanguage(Bash as any);
      break;
    case '.rs':
      parser.setLanguage(Rust as any);
      break;
    default:
      // unknown extensions fall back to line-based text scanning
      return { type: 'text', lines: source.split('\n'), source };
  }

  const tree = parser.parse(source);
  return { type: 'ast', tree, source, parser };
}
