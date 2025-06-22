# ByteguardX
ByteGuardX/
├── core/                            # Core scanning logic
│   ├── scanner.py                   # Main scan orchestrator
│   ├── file_handler.py              # Loads and traverses code files
│   ├── pattern_matcher.py           # Regex-based scanning
│   ├── ast_analyzer.py              # Python AST-based analysis
│   └── semgrep_wrapper.py           # Semgrep integration wrapper
│
├── analyzers/                       # Specialized vulnerability detectors
│   ├── secrets_detector.py          # Detect API keys, tokens, passwords
│   ├── dependency_checker.py        # Check pip/npm dependencies against CVEs
│   ├── ai_code_patterns.py          # Unsafe AI-generated code detection
│   ├── logic_analyzer.py            # Detect logic bugs, unreachable code
│   ├── security_vuln_detector.py    # SQLi, XSS, RCE, SSRF, etc.
│   └── quality_linter.py            # PEP8, flake8, style issues
│
├── ai_engine/                       # AI fix suggestions engine
│   ├── fix_generator.py             # Main logic for AI-generated fixes
│   ├── prompt_templates.py          # Prompt blueprints for LLMs
│   └── offline_model_handler.py     # Runs local LLMs (LLaMA, Ollama, etc.)
│
├── reporting/                       # Report generation modules
│   ├── report_builder.py            # Aggregates results from all analyzers
│   └── exporters/                   # Report output formats
│       ├── pdf_exporter.py          # PDF output (via ReportLab)
│       ├── html_exporter.py         # HTML output (via Jinja2)
│       └── json_exporter.py         # JSON output for integrations
│
├── hooks/                           # Git hook integration
│   ├── pre_commit_checker.py        # Real-time checks before Git commits
│   └── git_hook_installer.py        # Auto-installs hooks to .git/hooks
│
├── db/                              # Offline vulnerability & secrets DB
│   ├── cve_db.json                  # Cached CVEs (local copy of NVD, etc.)
│   ├── secrets_patterns.json        # Regex patterns for API keys, tokens
│   ├── ai_unsafe_patterns.json      # Common unsafe AI-generated code
│   └── safe_fixes.json              # Map of unsafe → AI-recommended fixes
│
├── ui/                              # Optional PyQt5 GUI
│   ├── main_window.py               # Main PyQt app interface
│   ├── scanner_page.py              # Scanner control UI
│   ├── results_viewer.py            # Displays scan results nicely
│   └── icons/                       # SVG or PNG icons for GUI
│       └── logo.svg
│
├── cli/                             # Command-line interface
│   └── cli.py                       # `python cli.py --scan .` style CLI
│
├── server/                          # Optional Flask server
│   └── api.py                       # Run local scan via HTTP (localhost)
│
├── plugins/                         # IDE plugin scaffolding
│   ├── vscode/                      # VS Code extension files
│   │   ├── extension.js
│   │   └── package.json
│   └── jetbrains/                   # JetBrains plugin boilerplate
│       └── plugin.xml
│
├── utils/                           # Common helpers
│   ├── config.py                    # Config handling (path, settings)
│   ├── logger.py                    # Standardized logging setup
│   └── decorators.py                # Shared decorators/utilities
│
├── tests/                           # Test suite
│   ├── test_scanner.py
│   ├── test_analyzers.py
│   ├── test_ai_engine.py
│   └── test_hooks.py
│
├── .gitignore
├── requirements.txt                 # Python deps
├── setup.py                         # Package setup
├── README.md
└── LICENSE
