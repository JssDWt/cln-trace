use std::fs::canonicalize;
use std::{fs::File, io::BufRead, io::BufReader, path::Path};

use bcc::{BPFBuilder, BccDebug, USDTContext};

pub const TRACEFS: &str = "/sys/kernel/debug/tracing";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} [binary]", args[0]);
        std::process::exit(1);
    }

    let binary = args[1].clone();

    let code = r#"
    #include <uapi/linux/ptrace.h>

    int do_trace(struct pt_regs *ctx) {
        uint64_t addr;
        char path[495];
        bpf_usdt_readarg(2, ctx, &addr);
        bpf_probe_read(&path, sizeof(path), (void *)addr);
        bpf_trace_printk("%s", path);
        return 0;
    };"#;

    let mut usdt_ctx = USDTContext::from_binary_path(canonicalize(binary)?)?;
    usdt_ctx.enable_probe("span_emit", "do_trace")?;
    let _b = BPFBuilder::new(code)?
        .add_usdt_context(usdt_ctx)?
        .debug(BccDebug::empty())
        .attach_usdt_ignore_pid(true)?
        .build()?;

    let p = format!("{}/trace_pipe", TRACEFS);
    let path = Path::new(&p);
    let f = File::open(path).unwrap();
    let mut reader = BufReader::new(f);

    println!("Starting listen loop");
    loop {
        let mut buf = String::with_capacity(1024);
        reader.read_line(&mut buf)?;
        if buf.starts_with("CPU:") {
            continue;
        }
        let msg = trace_parse(buf);
        println!("{}", msg)
    }
}

fn trace_parse(line: String) -> String {
    let line = &line[17..];
    let timestamp_end = line.find(':').unwrap();
    let line = &line[(timestamp_end + 1)..];
    let sym_end = line.find(':').unwrap();
    let msg = &line[sym_end + 2..];

    msg.to_owned()
}
