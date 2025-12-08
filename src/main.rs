// Copyright (c) 2024-2025 Ihor
// SPDX-License-Identifier: BSL-1.1
// See LICENSE file for details

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser)]
#[command(name = "adi")]
#[command(about = "ADI - AI-powered code indexer and search")]
#[command(version)]
struct Cli {
    /// Path to the project directory
    #[arg(short, long, default_value = ".")]
    project: PathBuf,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Index the project
    Index {
        /// Force re-index all files
        #[arg(short, long)]
        force: bool,
    },

    /// Search for symbols
    Search {
        /// Search query
        query: String,

        /// Maximum number of results
        #[arg(short, long, default_value = "10")]
        limit: usize,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Search for files
    Files {
        /// Search query
        query: String,

        /// Maximum number of results
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },

    /// Search for symbols by name
    Symbols {
        /// Search query
        query: String,

        /// Maximum number of results
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },

    /// Show project tree
    Tree {
        /// Maximum depth
        #[arg(short, long)]
        depth: Option<usize>,
    },

    /// Show project status
    Status,

    /// Show symbol details
    Show {
        /// Symbol ID
        id: i64,
    },

    /// Initialize ADI in a project
    Init,

    /// Show or set configuration
    Config {
        /// Configuration key
        key: Option<String>,

        /// Configuration value
        value: Option<String>,
    },

    /// Find usages of a symbol
    Usages {
        /// Symbol name or ID to find usages for
        query: String,

        /// Maximum number of results
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },

    /// Show call graph for a symbol (callers and callees)
    Callgraph {
        /// Symbol ID
        id: i64,

        /// Show callers (who calls this symbol)
        #[arg(long, default_value = "true")]
        callers: bool,

        /// Show callees (what this symbol calls)
        #[arg(long, default_value = "true")]
        callees: bool,
    },

    /// Show references to a symbol
    Refs {
        /// Symbol ID
        id: i64,

        /// Direction: "to" (who references this), "from" (what this references), or "both"
        #[arg(short, long, default_value = "to")]
        direction: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    let project_path = cli.project.canonicalize()?;

    match cli.command {
        Commands::Init => {
            init_project(&project_path)?;
        }
        Commands::Index { force } => {
            index_project(&project_path, force).await?;
        }
        Commands::Search { query, limit, format } => {
            search(&project_path, &query, limit, &format).await?;
        }
        Commands::Files { query, limit } => {
            search_files(&project_path, &query, limit).await?;
        }
        Commands::Symbols { query, limit } => {
            search_symbols(&project_path, &query, limit).await?;
        }
        Commands::Tree { depth } => {
            show_tree(&project_path, depth).await?;
        }
        Commands::Status => {
            show_status(&project_path).await?;
        }
        Commands::Show { id } => {
            show_symbol(&project_path, id).await?;
        }
        Commands::Config { key, value } => {
            config_cmd(&project_path, key, value)?;
        }
        Commands::Usages { query, limit } => {
            find_usages(&project_path, &query, limit).await?;
        }
        Commands::Callgraph { id, callers, callees } => {
            show_callgraph(&project_path, id, callers, callees).await?;
        }
        Commands::Refs { id, direction } => {
            show_refs(&project_path, id, &direction).await?;
        }
    }

    Ok(())
}

fn init_project(project_path: &PathBuf) -> Result<()> {
    let adi_dir = project_path.join(".adi");

    if adi_dir.exists() {
        println!("ADI already initialized in this project");
        return Ok(());
    }

    std::fs::create_dir_all(&adi_dir)?;
    std::fs::create_dir_all(adi_dir.join("tree"))?;
    std::fs::create_dir_all(adi_dir.join("tree/embeddings"))?;
    std::fs::create_dir_all(adi_dir.join("cache"))?;

    // Create default config
    let config = adi_core::Config::default();
    config.save_project(project_path)?;

    // Create .gitignore
    std::fs::write(
        adi_dir.join(".gitignore"),
        "# Ignore everything in .adi\n*\n!.gitignore\n!config.toml\n",
    )?;

    println!("Initialized ADI in {}", project_path.display());
    println!("Run 'adi index' to index the project");

    Ok(())
}

async fn index_project(project_path: &PathBuf, _force: bool) -> Result<()> {
    println!("Indexing project: {}", project_path.display());

    let adi = adi_core::Adi::open(project_path).await?;
    let progress = adi.index().await?;

    println!("\nIndexing complete:");
    println!("  Files processed: {}", progress.files_processed);
    println!("  Symbols indexed: {}", progress.symbols_indexed);

    if !progress.errors.is_empty() {
        println!("\nErrors ({}):", progress.errors.len());
        for error in progress.errors.iter().take(10) {
            println!("  - {}", error);
        }
        if progress.errors.len() > 10 {
            println!("  ... and {} more", progress.errors.len() - 10);
        }
    }

    Ok(())
}

async fn search(project_path: &PathBuf, query: &str, limit: usize, format: &str) -> Result<()> {
    let adi = adi_core::Adi::open(project_path).await?;
    let results = adi.search(query, limit).await?;

    if results.is_empty() {
        println!("No results found");
        return Ok(());
    }

    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&results)?;
            println!("{}", json);
        }
        _ => {
            println!("Found {} results:\n", results.len());
            for result in results {
                println!(
                    "  {} {} (score: {:.3})",
                    result.symbol.kind.as_str(),
                    result.symbol.name,
                    result.score
                );
                println!(
                    "    {}:{}",
                    result.symbol.file_path.display(),
                    result.symbol.location.start_line + 1
                );
                if let Some(sig) = &result.symbol.signature {
                    println!("    {}", sig);
                }
                println!();
            }
        }
    }

    Ok(())
}

async fn search_files(project_path: &PathBuf, query: &str, limit: usize) -> Result<()> {
    let adi = adi_core::Adi::open(project_path).await?;
    let results = adi.search_files(query, limit).await?;

    if results.is_empty() {
        println!("No files found");
        return Ok(());
    }

    println!("Found {} files:\n", results.len());
    for file in results {
        println!("  {} ({})", file.path.display(), file.language.as_str());
    }

    Ok(())
}

async fn search_symbols(project_path: &PathBuf, query: &str, limit: usize) -> Result<()> {
    let adi = adi_core::Adi::open(project_path).await?;
    let results = adi.search_symbols(query, limit).await?;

    if results.is_empty() {
        println!("No symbols found");
        return Ok(());
    }

    println!("Found {} symbols:\n", results.len());
    for symbol in results {
        println!(
            "  {} {} in {}:{}",
            symbol.kind.as_str(),
            symbol.name,
            symbol.file_path.display(),
            symbol.location.start_line + 1
        );
    }

    Ok(())
}

async fn show_tree(project_path: &PathBuf, _depth: Option<usize>) -> Result<()> {
    let adi = adi_core::Adi::open(project_path).await?;
    let tree = adi.get_tree()?;

    for file in tree.files {
        println!("{} ({})", file.path.display(), file.language.as_str());
        for symbol in file.symbols {
            print_symbol(&symbol, 1);
        }
    }

    Ok(())
}

fn print_symbol(symbol: &adi_core::SymbolNode, indent: usize) {
    let prefix = "  ".repeat(indent);
    println!("{}{} {}", prefix, symbol.kind.as_str(), symbol.name);
    for child in &symbol.children {
        print_symbol(child, indent + 1);
    }
}

async fn show_status(project_path: &PathBuf) -> Result<()> {
    let adi = adi_core::Adi::open(project_path).await?;
    let status = adi.status()?;

    println!("ADI Status:");
    println!("  Indexed files:    {}", status.indexed_files);
    println!("  Indexed symbols:  {}", status.indexed_symbols);
    println!("  Embedding model:  {}", status.embedding_model);
    println!("  Dimensions:       {}", status.embedding_dimensions);
    if let Some(last) = &status.last_indexed {
        println!("  Last indexed:     {}", last);
    }

    Ok(())
}

async fn show_symbol(project_path: &PathBuf, id: i64) -> Result<()> {
    let adi = adi_core::Adi::open(project_path).await?;
    let symbol = adi.get_symbol(adi_core::SymbolId(id))?;

    println!("Symbol: {}", symbol.name);
    println!("  Kind:     {}", symbol.kind.as_str());
    println!("  File:     {}", symbol.file_path.display());
    println!(
        "  Location: {}:{}-{}:{}",
        symbol.location.start_line + 1,
        symbol.location.start_col + 1,
        symbol.location.end_line + 1,
        symbol.location.end_col + 1
    );
    if let Some(sig) = &symbol.signature {
        println!("  Signature: {}", sig);
    }
    if let Some(doc) = &symbol.doc_comment {
        println!("  Doc: {}", doc);
    }

    Ok(())
}

fn config_cmd(project_path: &PathBuf, key: Option<String>, value: Option<String>) -> Result<()> {
    let config = adi_core::Config::load(project_path)?;

    match (key, value) {
        (None, None) => {
            // Show all config
            let toml = toml::to_string_pretty(&config)?;
            println!("{}", toml);
        }
        (Some(key), None) => {
            // Show specific key
            let toml = toml::to_string_pretty(&config)?;
            // Simple approach: just print the whole config
            println!("Key '{}' - full config:", key);
            println!("{}", toml);
        }
        (Some(_key), Some(_value)) => {
            // Set config value - would need more implementation
            println!("Setting config values is not yet implemented");
            println!("Edit .adi/config.toml directly");
        }
        _ => {}
    }

    Ok(())
}

async fn find_usages(project_path: &PathBuf, query: &str, limit: usize) -> Result<()> {
    let adi = adi_core::Adi::open(project_path).await?;

    // First, try to parse as symbol ID
    if let Ok(id) = query.parse::<i64>() {
        // Query is a symbol ID
        let usage = adi.get_symbol_usage(adi_core::SymbolId(id))?;
        print_symbol_usage(&usage, &adi);
        return Ok(());
    }

    // Otherwise, search for symbols by name
    let symbols = adi.find_symbols_by_name(query)?;

    if symbols.is_empty() {
        // Try FTS search as fallback
        let symbols = adi.search_symbols(query, limit).await?;
        if symbols.is_empty() {
            println!("No symbols found matching '{}'", query);
            return Ok(());
        }

        println!("Found {} symbols matching '{}':\n", symbols.len(), query);
        for symbol in &symbols {
            let ref_count = adi.get_reference_count(symbol.id).unwrap_or(0);
            println!(
                "  [{}] {} {} ({} references)",
                symbol.id.0,
                symbol.kind.as_str(),
                symbol.name,
                ref_count
            );
            println!("    {}:{}", symbol.file_path.display(), symbol.location.start_line + 1);
        }
        println!("\nUse 'adi usages <id>' to see detailed usage for a specific symbol");
        return Ok(());
    }

    // If only one symbol matches, show its usage directly
    if symbols.len() == 1 {
        let usage = adi.get_symbol_usage(symbols[0].id)?;
        print_symbol_usage(&usage, &adi);
    } else {
        println!("Found {} symbols named '{}':\n", symbols.len(), query);
        for symbol in &symbols {
            let ref_count = adi.get_reference_count(symbol.id).unwrap_or(0);
            println!(
                "  [{}] {} {} ({} references)",
                symbol.id.0,
                symbol.kind.as_str(),
                symbol.name,
                ref_count
            );
            println!("    {}:{}", symbol.file_path.display(), symbol.location.start_line + 1);
        }
        println!("\nUse 'adi usages <id>' to see detailed usage for a specific symbol");
    }

    Ok(())
}

fn print_symbol_usage(usage: &adi_core::SymbolUsage, adi: &adi_core::Adi) {
    let symbol = &usage.symbol;

    println!("Symbol: {} {}", symbol.kind.as_str(), symbol.name);
    println!("  File: {}:{}", symbol.file_path.display(), symbol.location.start_line + 1);
    if let Some(sig) = &symbol.signature {
        println!("  Signature: {}", sig);
    }
    println!("  References: {}", usage.reference_count);

    // Show exact usage locations (deduplicated by file:line)
    if let Ok(refs) = adi.get_references_to(symbol.id) {
        if !refs.is_empty() {
            // Group by file:line to avoid duplicates
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            let unique_refs: Vec<_> = refs.iter()
                .filter(|r| {
                    if let Ok(from_symbol) = adi.get_symbol(r.from_symbol_id) {
                        let key = format!("{}:{}", from_symbol.file_path.display(), r.location.start_line);
                        seen.insert(key)
                    } else {
                        false
                    }
                })
                .collect();

            println!("\nUsage locations ({}):", unique_refs.len());
            for r in &refs {
                if let Ok(from_symbol) = adi.get_symbol(r.from_symbol_id) {
                    let key = format!("{}:{}", from_symbol.file_path.display(), r.location.start_line);
                    // Only print first occurrence per location
                    if seen.remove(&key) {
                        println!(
                            "  {}:{}:{} ({}) in {} {}",
                            from_symbol.file_path.display(),
                            r.location.start_line + 1,
                            r.location.start_col + 1,
                            r.kind.as_str(),
                            from_symbol.kind.as_str(),
                            from_symbol.name
                        );
                    }
                }
            }
        }
    }

    if !usage.callees.is_empty() {
        println!("\nThis symbol references ({}):", usage.callees.len());
        for callee in &usage.callees {
            println!(
                "  {} {} ({}:{})",
                callee.kind.as_str(),
                callee.name,
                callee.file_path.display(),
                callee.location.start_line + 1
            );
        }
    }

    if usage.callers.is_empty() && usage.callees.is_empty() {
        println!("\nNo references found in indexed code.");
    }
}

async fn show_callgraph(project_path: &PathBuf, id: i64, show_callers: bool, show_callees: bool) -> Result<()> {
    let adi = adi_core::Adi::open(project_path).await?;
    let symbol = adi.get_symbol(adi_core::SymbolId(id))?;

    println!("Call graph for: {} {}", symbol.kind.as_str(), symbol.name);
    println!("  {}:{}", symbol.file_path.display(), symbol.location.start_line + 1);

    if show_callers {
        let callers = adi.get_callers(adi_core::SymbolId(id))?;
        println!("\nCallers ({}):", callers.len());
        if callers.is_empty() {
            println!("  (none)");
        } else {
            for caller in &callers {
                println!(
                    "  <- [{}] {} {} ({}:{})",
                    caller.id.0,
                    caller.kind.as_str(),
                    caller.name,
                    caller.file_path.display(),
                    caller.location.start_line + 1
                );
            }
        }
    }

    if show_callees {
        let callees = adi.get_callees(adi_core::SymbolId(id))?;
        println!("\nCallees ({}):", callees.len());
        if callees.is_empty() {
            println!("  (none)");
        } else {
            for callee in &callees {
                println!(
                    "  -> [{}] {} {} ({}:{})",
                    callee.id.0,
                    callee.kind.as_str(),
                    callee.name,
                    callee.file_path.display(),
                    callee.location.start_line + 1
                );
            }
        }
    }

    Ok(())
}

async fn show_refs(project_path: &PathBuf, id: i64, direction: &str) -> Result<()> {
    let adi = adi_core::Adi::open(project_path).await?;
    let symbol = adi.get_symbol(adi_core::SymbolId(id))?;

    println!("References for: {} {}", symbol.kind.as_str(), symbol.name);
    println!("  {}:{}", symbol.file_path.display(), symbol.location.start_line + 1);

    let show_to = direction == "to" || direction == "both";
    let show_from = direction == "from" || direction == "both";

    if show_to {
        let refs_to = adi.get_references_to(adi_core::SymbolId(id))?;
        println!("\nReferences TO this symbol ({}):", refs_to.len());
        if refs_to.is_empty() {
            println!("  (none)");
        } else {
            for r in &refs_to {
                let from_symbol = adi.get_symbol(r.from_symbol_id)?;
                println!(
                    "  {} at line {} from {} {}",
                    r.kind.as_str(),
                    r.location.start_line + 1,
                    from_symbol.kind.as_str(),
                    from_symbol.name
                );
            }
        }
    }

    if show_from {
        let refs_from = adi.get_references_from(adi_core::SymbolId(id))?;
        println!("\nReferences FROM this symbol ({}):", refs_from.len());
        if refs_from.is_empty() {
            println!("  (none)");
        } else {
            for r in &refs_from {
                let to_symbol = adi.get_symbol(r.to_symbol_id)?;
                println!(
                    "  {} at line {} to {} {}",
                    r.kind.as_str(),
                    r.location.start_line + 1,
                    to_symbol.kind.as_str(),
                    to_symbol.name
                );
            }
        }
    }

    Ok(())
}
