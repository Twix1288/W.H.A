import ast
import sys
import json

class SecurityScanner(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []

    def add_finding(self, severity, category, message, line):
        self.vulnerabilities.append({
            "severity": severity,
            "category": category,
            "message": message,
            "line": line
        })

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name in ['subprocess', 'os']:
                self.add_finding("WARNING", "Dangerous Import", f"Imported module '{alias.name}' which can execute arbitrary system commands.", node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module in ['subprocess', 'os']:
            self.add_finding("WARNING", "Dangerous Import", f"Imported from '{node.module}' which can execute arbitrary system commands.", node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node):
        # Check for eval() or exec()
        if isinstance(node.func, ast.Name):
            if node.func.id in ['eval', 'exec']:
                self.add_finding("CRITICAL", "Dynamic Execution", f"Usage of '{node.func.id}' allows execution of arbitrary untrusted code strings.", node.lineno)
            elif node.func.id == 'open':
                self.add_finding("WARNING", "File Access", "Direct file access via 'open()'. Ensure this does not read outside the container workspace.", node.lineno)
        
        # Check for os.system
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os' and node.func.attr == 'system':
                self.add_finding("CRITICAL", "System Command Execution", "Usage of 'os.system' allows shell command execution.", node.lineno)
        
        self.generic_visit(node)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No file provided"}))
        sys.exit(1)

    target_file = sys.argv[1]
    try:
        with open(target_file, 'r', encoding='utf-8') as f:
            code = f.read()
            tree = ast.parse(code)
            
            scanner = SecurityScanner()
            scanner.visit(tree)
            
            print(json.dumps(scanner.vulnerabilities))
            
    except SyntaxError as e:
        print(json.dumps([{"severity": "ERROR", "category": "Syntax Error", "message": str(e), "line": e.lineno}]))
    except Exception as e:
        print(json.dumps([{"severity": "ERROR", "category": "Analysis Failed", "message": str(e), "line": 0}]))
