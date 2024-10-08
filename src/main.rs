use std::{fs::canonicalize, time::Duration};

use bcc::{trace_read, BPFBuilder, BccDebug, USDTContext};
use serde_json::Value;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
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
        bpf_trace_printk("%s\n", path);
        return 0;
    };"#;

    let mut usdt_ctx = USDTContext::from_binary_path(canonicalize(binary)?)?;
    usdt_ctx.enable_probe("span_emit", "do_trace")?;
    let _b = BPFBuilder::new(code)?
        .add_usdt_context(usdt_ctx)?
        .debug(BccDebug::empty())
        .attach_usdt_ignore_pid(true)?
        .build()?;

    let (tx, mut rx) = tokio::sync::mpsc::channel(1024);

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let mut spans: Vec<Value> = Vec::new();
            while let Ok(span) = rx.try_recv() {
                spans.push(span);
            }

            let json = match serde_json::to_string(&spans) {
                Ok(json) => json,
                Err(e) => {
                    println!("Failed to serialize spans: {:?}", e);
                    continue;
                },
            };
            println!("{}", json);
        }
    });

    loop {
        let line = trace_read()?;
        let msg = trace_parse(line);
        
        let v = serde_json::from_str::<Vec<Value>>(&msg)?;

        tx.send(v[0].clone()).await?;
    }
}

fn trace_parse(line: String) -> String {
    let line = &line[17..];
    let timestamp_end = line.find(":").unwrap();
    let line = &line[(timestamp_end + 1)..];
    let sym_end = line.find(":").unwrap();
    let msg = &line[sym_end + 2..];

    msg.to_owned()
}
