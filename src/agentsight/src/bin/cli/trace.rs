//! Trace subcommand - agent activity tracing
//!
//! Linux: full eBPF-based tracing (probes → parser → aggregator → storage).
//! macOS: trajectory collection only (JSONL file scanning → ATIF → SQLite).

use structopt::StructOpt;

/// Trace subcommand
#[derive(Debug, StructOpt, Clone)]
pub struct TraceCommand {
    /// Enable verbose/debug output.
    #[structopt(short, long)]
    pub verbose: bool,

    /// Run as daemon in background (Linux only)
    #[cfg(target_os = "linux")]
    #[structopt(long)]
    pub daemon: bool,
    /// PID file path for daemon mode (Linux only)
    #[cfg(target_os = "linux")]
    #[structopt(long, default_value = "/tmp/agentsight.pid")]
    pub pid_file: String,

    /// Enable file watch probe (monitors .jsonl file opens from traced processes)
    #[cfg(target_os = "linux")]
    #[structopt(long)]
    pub enable_filewatch: bool,

    /// Path to JSON configuration file (Linux only)
    #[cfg(target_os = "linux")]
    #[structopt(short, long, default_value = "/etc/agentsight/config.json")]
    pub config: String,
}

impl TraceCommand {
    pub fn execute(&self) {
        #[cfg(target_os = "linux")]
        {
            self.execute_linux();
        }

        #[cfg(not(target_os = "linux"))]
        {
            self.execute_local();
        }
    }
}

// ─── Linux: eBPF + trajectory collector ──────────────────────────────────────

#[cfg(target_os = "linux")]
impl TraceCommand {
    fn execute_linux(&self) {
        if self.daemon {
            self.run_as_daemon();
            return;
        }

        self.run_tracing();
    }

    /// Run as daemon process
    fn run_as_daemon(&self) {
        use daemonize::Daemonize;

        println!("Starting agentsight in daemon mode...");
        println!("PID file: {}", self.pid_file);

        let daemonize = Daemonize::new()
            .pid_file(&self.pid_file)
            .chown_pid_file(true)
            .working_directory("/tmp");

        match daemonize.start() {
            Ok(_) => {
                self.run_tracing();
            }
            Err(e) => {
                eprintln!("Failed to daemonize: {e}");
                std::process::exit(1);
            }
        }
    }

    /// Run the actual tracing logic using AgentSight
    fn run_tracing(&self) {
        use agentsight::{AgentSight, AgentsightConfig};

        // Build AgentSight config (empty target_pids means trace all processes).
        // Note: `traceEnabled=false` from agentsight.json does NOT stop the agent
        // — token consumption (LLM call) data must always be collected by default.
        // The toggle only affects the SLS upload layer (LogtailExporter): when
        // traceEnabled=false, conversation content fields (gen_ai.input.messages /
        // gen_ai.output.messages) are dropped from uploaded records, but token
        // metadata (model, provider, token counts, etc.) is still uploaded.
        let config = AgentsightConfig::new()
            .set_verbose(self.verbose)
            .set_enable_filewatch(self.enable_filewatch)
            .set_config_path(std::path::PathBuf::from(&self.config));

        // Create AgentSight (auto-attaches probes and starts polling)
        let mut sight = match AgentSight::new(config) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to create AgentSight: {e}");
                std::process::exit(1);
            }
        };

        // Register Ctrl+C handler for graceful shutdown.
        // This ensures AgentSight is dropped normally, which triggers
        // Storage::drop → WAL checkpoint, flushing data to the main db file.
        let running = sight.running_flag();
        ctrlc::set_handler(move || {
            log::info!("Ctrl+C received, shutting down gracefully...");
            running.store(false, std::sync::atomic::Ordering::SeqCst);
        })
        .expect("Failed to set Ctrl+C handler");

        // Run event loop (blocks until running flag is set to false)
        match sight.run() {
            Ok(count) => {
                println!("\nReceived {count} events total");
                println!("Token usage data saved. Use 'agentsight token' to query.");
            }
            Err(e) => {
                eprintln!("Error during tracing: {e}");
                std::process::exit(1);
            }
        }
        // `sight` drops here → Storage::drop → checkpoint
    }
}

// ─── macOS: trajectory collector only (no eBPF) ──────────────────────────────

#[cfg(not(target_os = "linux"))]
impl TraceCommand {
    fn execute_local(&self) {
        use std::sync::atomic::{AtomicBool, Ordering};

        let db_path = dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("agentsight")
            .join("trajectories.db");

        if let Some(parent) = db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let store = match agentsight_trajectory_collector::TrajectoryStore::new_with_path(&db_path)
        {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to open trajectory store at {db_path:?}: {e}");
                std::process::exit(1);
            }
        };

        let scan_dirs = agentsight::local::server::local_trajectory_scan_dirs();
        let config = agentsight_trajectory_collector::CollectorConfig {
            scan_interval_secs: 300,
            scan_dirs,
            db_path: db_path.clone(),
        };

        // Run one immediate scan.
        agentsight_trajectory_collector::scan_once(&store, &config);

        let stop = Arc::new(AtomicBool::new(true));
        let stop_clone = Arc::clone(&stop);

        ctrlc::set_handler(move || {
            println!("\nShutting down trajectory collector...");
            stop_clone.store(false, Ordering::SeqCst);
        })
        .ok();

        println!("Trajectory collector running. Press Ctrl+C to stop.");
        agentsight_trajectory_collector::run_collector_loop(&config, &stop);
    }
}

#[cfg(not(target_os = "linux"))]
use std::sync::Arc;
