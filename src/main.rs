use crate::trace::TcpCaSkelBuilder;

mod trace {
    // Skeleton rely on `libbpf_rs` being present in their "namespace". Because
    // we renamed the libbpf-rs dependency, we have to make it available under
    // the expected name here for the skeleton itself to work. None of this is
    // generally necessary, but it enables some niche use cases.
    use the_original_libbpf_rs as libbpf_rs;

    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/trace.skel.rs"
    ));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} [output_path] [binary]", args[0]);
        std::process::exit(1);
    }

    let output_path = args[1];
    let binary = args[2];

    let (tx, rx) = tokio::sync::mpsc::channel(1024);

    tokio::spawn(async move {
        loop {

        }
    })
}
