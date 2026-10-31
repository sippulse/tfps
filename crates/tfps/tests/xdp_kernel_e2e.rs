use std::net::Ipv4Addr;
use std::path::Path;

use tfps::xdp::{Blocklist, Enforcer};

#[test]
#[ignore = "requires root, CAP_BPF/CAP_NET_ADMIN, a clang-built tfps_xdp.o and an XDP-capable interface; set TFPS_XDP_OBJ and optionally TFPS_XDP_IFACE"]
fn a_block_reaches_the_kernel_map_and_can_be_lifted() {
    let obj = std::env::var("TFPS_XDP_OBJ").expect("set TFPS_XDP_OBJ to a clang-built tfps_xdp.o");
    let iface = std::env::var("TFPS_XDP_IFACE").unwrap_or_else(|_| "lo".to_string());
    let ip = Ipv4Addr::new(198, 51, 100, 42);

    let mut enforcer = Enforcer::attach(
        Path::new("/nonexistent/tfps-drop"),
        Path::new(&obj),
        &iface,
        &[5999],
    )
    .expect("attach XDP");
    enforcer.block(ip, 60).expect("block in the kernel map");
    assert_eq!(enforcer.blocked_count(), 1, "one source is condemned");

    let mut live = Blocklist::open(None).expect("open the live map");
    let entries = live.entries();
    assert!(
        entries.iter().any(|(candidate, _)| *candidate == ip),
        "the block is visible from the live map: {entries:?}"
    );
    assert!(
        live.remove(ip).expect("lift the block"),
        "the source was there"
    );
    assert!(
        !live.entries().iter().any(|(candidate, _)| *candidate == ip),
        "the source is gone after unban"
    );
}
