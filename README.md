# ADI Code Indexer - CLI

Command-line interface for ADI Code Indexer - a semantic code indexing and search tool.

## Overview

`adi-cli` provides a terminal interface for indexing codebases and performing semantic code searches. It wraps `adi-core` functionality in an ergonomic CLI experience.

## Installation

```bash
cargo build --release
# Binary available at: target/release/adi
```

## Commands

```
adi init           Initialize ADI Code Indexer in current directory
adi index          Index the codebase
adi search <query> Semantic search across code
adi symbols        List indexed symbols
adi files          List indexed files
adi tree           Show code structure tree
adi status         Show indexing status
adi show <symbol>  Show symbol details
adi config         Manage configuration
```

## Quick Start

```bash
# Initialize in your project
cd /path/to/your/project
adi init

# Index the codebase
adi index

# Search for code
adi search "authentication middleware"
```

## Configuration

Configuration is stored in `.adi/config.toml` in your project directory.

## License

BSL-1.1 - See [LICENSE](LICENSE) for details.
