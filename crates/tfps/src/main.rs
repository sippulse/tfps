//! TFPS — observa SIP no fio, aprende o comportamento de cada origem, e decide.
//!
//! Captura por `AF_PACKET`/`SOCK_DGRAM`, que engata no netdev e **não abre socket UDP**:
//! o softswitch mantém o bind dele e não percebe nada (`SPEC.md` §2).
//!
//! O perímetro já impõe: origem condenada por user-agent ou por injeção na URI vai para
//! um mapa consultado pelo XDP, e some do sngrep. O veredito **de fraude** ainda não é
//! imposto — falta a forja do `603`.
//!
//! Precisa de `CAP_NET_RAW` (captura), `CAP_BPF` e `CAP_NET_ADMIN` (XDP).

mod apiban;
mod config;
mod store;
mod xdp;

use std::collections::BTreeMap;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use socket2::{Domain, Protocol, Socket, Type};
use tfps_core::dialplan::DialPlan;
use tfps_core::engine::{Decision, Engine, Mode};
use tfps_core::net::{classify_other, parse_ipv4_udp, tcp_ports, NotUdp};
use tfps_core::novelty::Timestamp;

/// `AF_PACKET` no Linux. O `socket2` não expõe constante para esta família, então o
/// valor entra direto — é estável na ABI do Linux desde sempre.
const AF_PACKET: i32 = 17;

/// `ETH_P_IP` em ordem de rede, como o `socket(2)` de `AF_PACKET` espera.
const ETH_P_IP_BE: i32 = 0x0008;

/// MTU folgado: SIP sobre UDP raramente passa disso, e o que passa fragmenta.
const BUF: usize = 65_536;

struct Args {
    ports: Vec<u16>,
    intl_prefixes: Vec<String>,
    learn_secs: u32,
    stats_every: u64,
    verbose: bool,
    debug_unparsed: bool,
    xdp_obj: PathBuf,
    shared_map: PathBuf,
    iface: Option<String>,
    block_ttl: u64,
    no_enforce: bool,
    db: PathBuf,
    checkpoint_every: u64,
    apiban_key: Option<String>,
    signatures: Option<PathBuf>,
    config: PathBuf,
    /// Plano de discagem por peer, vindo do arquivo. Declarar bate aprender por valer já
    /// na primeira chamada daquele peer.
    peer_plans: Vec<(Ipv4Addr, DialPlan)>,
    /// Quais flags o operador passou de fato — o arquivo só preenche o que ficou de fora.
    given: std::collections::HashSet<String>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            ports: vec![5060],
            // Cobre as formas mais comuns; o `SPEC.md` §4 manda declarar por central.
            intl_prefixes: vec!["+".into(), "00".into(), "011".into(), "9011".into()],
            learn_secs: 30 * 24 * 3600,
            stats_every: 60,
            verbose: false,
            debug_unparsed: false,
            xdp_obj: PathBuf::from(xdp::DEFAULT_OBJ),
            shared_map: PathBuf::from(xdp::SIPVAULT_DROP_MAP),
            iface: None,
            // Uma hora. Bloqueio de perímetro precisa se desfazer sozinho, e scanner que
            // volta é rebloqueado no primeiro pacote — o custo de errar é uma hora.
            block_ttl: 3600,
            no_enforce: false,
            db: PathBuf::from(store::DEFAULT_PATH),
            // Cinco minutos. Perder isso num corte de energia custa cinco minutos de
            // aprendizado — e checkpoint por pacote seria gargalo de escrita.
            checkpoint_every: 300,
            apiban_key: None,
            signatures: None,
            config: PathBuf::from(config::DEFAULT_PATH),
            peer_plans: Vec::new(),
            given: std::collections::HashSet::new(),
        }
    }
}

fn usage() -> &'static str {
    "\
tfps — prevenção de fraude IRSF em redes SIP

USO: tfps [opções]

  --ports 5060,5080        portas SIP a observar          (padrão: 5060)
  --intl +,00,011,9011     prefixos de discagem internacional
  --learn-days N           dias em modo de aprendizado    (padrão: 30)
  --active                 pula o aprendizado (equivale a --learn-days 0)
  --stats-every N          segundos entre relatórios      (padrão: 60)
  -v, --verbose            imprime cada tentativa internacional
      --debug-unparsed     mostra o início do payload que não parseou
      --iface eth0         interface para o XDP        (padrão: rota default)
      --xdp-obj PATH       objeto BPF próprio          (padrão: /usr/local/lib/tfps/tfps_xdp.o)
      --drop-map PATH      mapa de drop já fixado      (padrão: mapa do SipVault)
      --block-ttl N        segundos de bloqueio        (padrão: 3600, 0 = sem expirar)
      --no-enforce         só observa, não carrega XDP
      --db PATH            base SQLite                 (padrão: /var/lib/tfps/tfps.db)
      --no-db              não persiste (aprendizado morre no restart)
      --checkpoint-every N segundos entre gravações    (padrão: 300)
      --apiban-key KEY     integra o APIBAN (opcional, em segundo plano)
      --signatures PATH    arquivo que ACRESCENTA assinaturas às embutidas
      --config PATH        configuração        (padrão: /etc/tfps/config.json)
  -h, --help               esta ajuda

Captura por AF_PACKET; não abre socket UDP e não conflita com o softswitch.
Requer CAP_NET_RAW (rode como root).
"
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        a.given.insert(arg.clone());
        let mut next = |name: &str| it.next().ok_or_else(|| format!("{name} exige um valor"));
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{}", usage());
                std::process::exit(0);
            }
            "--ports" => {
                a.ports = next("--ports")?
                    .split(',')
                    .map(|p| {
                        p.trim()
                            .parse::<u16>()
                            .map_err(|e| format!("porta inválida: {e}"))
                    })
                    .collect::<Result<_, _>>()?;
            }
            "--intl" => {
                a.intl_prefixes = next("--intl")?
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
            }
            "--learn-days" => {
                let d: u32 = next("--learn-days")?.parse().map_err(|e| format!("{e}"))?;
                a.learn_secs = d * 24 * 3600;
            }
            "--active" => a.learn_secs = 0,
            "--stats-every" => {
                a.stats_every = next("--stats-every")?.parse().map_err(|e| format!("{e}"))?;
            }
            "-v" | "--verbose" => a.verbose = true,
            "--debug-unparsed" => a.debug_unparsed = true,
            "--xdp-obj" => a.xdp_obj = PathBuf::from(next("--xdp-obj")?),
            "--drop-map" => a.shared_map = PathBuf::from(next("--drop-map")?),
            "--iface" => a.iface = Some(next("--iface")?),
            "--block-ttl" => {
                a.block_ttl = next("--block-ttl")?.parse().map_err(|e| format!("{e}"))?;
            }
            "--no-enforce" => a.no_enforce = true,
            "--db" => a.db = PathBuf::from(next("--db")?),
            "--no-db" => a.db = PathBuf::new(),
            "--apiban-key" => a.apiban_key = Some(next("--apiban-key")?),
            "--signatures" => a.signatures = Some(PathBuf::from(next("--signatures")?)),
            "--config" => a.config = PathBuf::from(next("--config")?),
            "--checkpoint-every" => {
                a.checkpoint_every = next("--checkpoint-every")?
                    .parse()
                    .map_err(|e| format!("{e}"))?;
            }
            other => return Err(format!("opção desconhecida: {other}")),
        }
    }
    if a.ports.is_empty() {
        return Err("nenhuma porta a observar".into());
    }
    Ok(a)
}

/// Aplica o arquivo sobre os padrões, **sem sobrepor o que veio na linha de comando**.
///
/// Precedência: linha de comando > arquivo > padrão embutido. É a ordem que não surpreende
/// ninguém, e a que permite depurar em produção sem editar arquivo.
fn apply_config(a: &mut Args, c: &config::Config) {
    macro_rules! unless_given {
        ($flag:literal, $field:ident, $val:expr) => {
            if !a.given.contains($flag) {
                if let Some(v) = $val {
                    a.$field = v;
                }
            }
        };
    }
    unless_given!("--ports", ports, c.ports.clone());
    unless_given!("--intl", intl_prefixes, c.intl_prefixes.clone());
    unless_given!("--stats-every", stats_every, c.stats_every);
    unless_given!("--block-ttl", block_ttl, c.block_ttl);
    unless_given!("--checkpoint-every", checkpoint_every, c.checkpoint_every);
    unless_given!("--db", db, c.db.clone());
    unless_given!("--xdp-obj", xdp_obj, c.xdp_obj.clone());
    unless_given!("--drop-map", shared_map, c.drop_map.clone());

    if !a.given.contains("--iface") && c.iface.is_some() {
        a.iface = c.iface.clone();
    }
    if !a.given.contains("--apiban-key") && c.apiban_key.is_some() {
        a.apiban_key = c.apiban_key.clone();
    }
    if !a.given.contains("--learn-days") && !a.given.contains("--active") {
        if let Some(d) = c.learn_days {
            a.learn_secs = d.saturating_mul(24 * 3600);
        }
    }

    for (ip, pc) in &c.peers {
        match ip.parse::<Ipv4Addr>() {
            Ok(addr) => {
                let mut plan = DialPlan::new(pc.intl_prefixes.clone());
                if pc.bare_e164 {
                    plan = plan.with_bare_e164();
                }
                a.peer_plans.push((addr, plan));
            }
            // Peer com IP inválido é erro de digitação que faria o operador acreditar
            // ter declarado um plano que não vale. Nunca em silêncio.
            Err(e) => eprintln!("AVISO: peer \"{ip}\" no config não é um IPv4 válido ({e})"),
        }
    }
}

fn now() -> Timestamp {
    Timestamp(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0),
    )
}

fn main() -> ExitCode {
    let mut extra_signatures: Vec<String> = Vec::new();
    let mut extra_injection: Vec<String> = Vec::new();
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("erro: {e}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };

    let mut args = args;
    match config::load(&args.config) {
        config::Loaded::File(c, path) => {
            apply_config(&mut args, &c);
            println!("  configuração      : {}", path.display());
            // As assinaturas do arquivo entram depois que o motor existe; guardadas aqui.
            extra_signatures = c.signatures.clone();
            extra_injection = c.injection.clone();
        }
        config::Loaded::Absent => {}
        config::Loaded::Broken(e) => {
            // Configuração quebrada ignorada em silêncio faria o operador acreditar
            // ter declarado algo que não vale.
            eprintln!("ALARME: configuração inválida, usando padrões — {e}");
        }
    }
    let args = args;

    let start = now();

    // A base abre antes do motor porque ela decide **quando o aprendizado começou** —
    // sem isso, cada restart reiniciaria os 30 dias e a contagem regressiva mentiria.
    let db = if args.db.as_os_str().is_empty() {
        None
    } else {
        match store::Store::open(&args.db) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("ALARME: sem persistência — {e}");
                eprintln!("        o aprendizado será perdido no próximo restart.");
                None
            }
        }
    };

    let learn_from = db
        .as_ref()
        .map(|d| d.learning_started(start.0))
        .unwrap_or(start.0);

    let mode = if args.learn_secs == 0 {
        Mode::Active
    } else {
        Mode::Learning {
            until: Timestamp(learn_from.saturating_add(args.learn_secs)),
        }
    };

    let plan = DialPlan::new(args.intl_prefixes.clone());
    let mut engine = Engine::new(plan, mode);

    // Assinaturas **acrescentam** às embutidas; nunca substituem. Substituir faria quem
    // escreve três linhas perder as 18 de fábrica sem perceber.
    for sig in &extra_signatures {
        engine.noise_filter.add_signature(sig);
    }
    for pat in &extra_injection {
        engine.noise_filter.add_injection(pat);
    }
    for (ip, plan) in &args.peer_plans {
        engine.declare_dial_plan(*ip, plan.clone());
    }
    if !args.peer_plans.is_empty() {
        println!("  planos declarados : {} peers", args.peer_plans.len());
    }
    if let Some(path) = args.signatures.as_ref() {
        match std::fs::read_to_string(path) {
            Ok(txt) => {
                let mut ua = 0usize;
                let mut inj = 0usize;
                for line in txt.lines() {
                    match line.trim().split_once(char::is_whitespace) {
                        Some(("injection", rest)) => {
                            engine.noise_filter.add_injection(rest);
                            inj += 1;
                        }
                        _ => {
                            engine.noise_filter.add_signature(line);
                            ua += 1;
                        }
                    }
                }
                println!(
                    "  assinaturas extras: {ua} de user-agent, {inj} de injeção ({})",
                    path.display()
                );
            }
            Err(e) => eprintln!("AVISO: não consegui ler {}: {e}", path.display()),
        }
    }
    let (ua_int, ua_ext) = engine.noise_filter.signature_count();
    let (inj_int, inj_ext) = engine.noise_filter.injection_count();

    if let Some(d) = db.as_ref() {
        match d.load_into(&mut engine) {
            Ok((p, c)) if p > 0 || c > 0 => {
                println!("  estado restaurado : {p} pares, {c} países por peer");
            }
            Ok(_) => println!("  estado restaurado : base vazia (primeira execução)"),
            Err(e) => eprintln!("AVISO: não consegui restaurar o estado: {e}"),
        }
    }

    println!("tfps {} — iniciando", env!("CARGO_PKG_VERSION"));
    println!("  portas observadas : {:?}", args.ports);
    println!("  prefixos intl     : {:?}", args.intl_prefixes);
    match mode {
        // O modo é anunciado alto e repetido nos relatórios: o diferencial declarado do
        // projeto contra o fail2ban é que o incumbente falha em silêncio (`SPEC.md` §12).
        Mode::Active => println!("  modo              : ATIVO — bloquearia desde já"),
        Mode::Learning { until } => println!(
            "  modo              : APRENDENDO por {} dias (até {}), NÃO bloqueia",
            args.learn_secs / 86400,
            until.0
        ),
    }
    // Imposição: carrega o XDP, ou avisa alto e segue só observando. Nunca fingir.
    let mut enforcer = if args.no_enforce {
        println!("  imposição         : DESLIGADA por --no-enforce (só observa)");
        None
    } else {
        let iface = args
            .iface
            .clone()
            .or_else(xdp::default_interface)
            .unwrap_or_else(|| "eth0".to_string());
        match xdp::Enforcer::attach(&args.shared_map, &args.xdp_obj, &iface, &args.ports) {
            Ok(e) => {
                println!("  imposição         : {} — lixo some do sngrep", e.mode);
                println!("  bloqueio expira em: {}s", args.block_ttl);
                Some(e)
            }
            Err(err) => {
                // Requisito do SPEC §12: um antifraude que aparenta proteger sem
                // proteger é exatamente a crítica que este projeto faz ao incumbente.
                eprintln!("ALARME: imposição INATIVA — {err}");
                eprintln!("        o sistema vai OBSERVAR mas NÃO vai bloquear nada.");
                println!("  imposição         : INATIVA (ver alarme acima)");
                None
            }
        }
    };
    println!(
        "  perímetro         : {ua_int} user-agents (+{ua_ext} do arquivo), \
         {inj_int} padrões de injeção (+{inj_ext})"
    );

    let sock = match Socket::new(
        Domain::from(AF_PACKET),
        Type::DGRAM,
        Some(Protocol::from(ETH_P_IP_BE)),
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("erro: não consegui abrir o socket de captura: {e}");
            eprintln!("      AF_PACKET exige CAP_NET_RAW — rode como root.");
            return ExitCode::FAILURE;
        }
    };

    // Timeout de leitura para que o laço acorde mesmo sem tráfego. **Sem isto o alarme
    // de silêncio nunca dispara**: ele ficaria dentro do laço que só roda quando chega
    // pacote, e um sistema que não vê nada ficaria mudo — que é precisamente o modo de
    // falha do fail2ban que este projeto usa como diferencial (`SPEC.md` §12).
    if let Err(e) = sock.set_read_timeout(Some(Duration::from_secs(1))) {
        eprintln!("aviso: não consegui armar timeout de leitura: {e}");
        eprintln!("       o alarme de silêncio pode não disparar em link parado.");
    }

    // `socket2::Socket` implementa `Read`, o que permite um buffer normal e dispensa
    // `MaybeUninit` — e portanto dispensa `unsafe`, que o workspace proíbe.
    let mut sock = sock;
    let mut buf = vec![0u8; BUF];
    let mut last_report = start.0;
    let mut seen_ports: BTreeMap<u16, u64> = BTreeMap::new();
    // APIBAN em thread separada: HTTP nunca toca o caminho do pacote. Foi o `rest_get()`
    // síncrono por INVITE que limitou o TFPS 2023 a ~26 chamadas/s.
    let apiban_rx = args.apiban_key.as_ref().map(|k| {
        println!("  APIBAN            : ligado, sincronização em segundo plano");
        apiban::spawn(k.clone(), None)
    });

    let mut nothing_seen_warned = false;
    let mut apiban_total = 0u64;
    let mut db = db;
    let mut last_checkpoint = start.0;
    // Pontos cegos: contados para poder virar aviso. Ignorar em silêncio seria repetir
    // a falha que o projeto usa como diferencial contra o fail2ban.
    let (mut n_ipv6, mut n_tcp, mut n_frag) = (0u64, 0u64, 0u64);
    let mut blind_warned = false;

    loop {
        let n = match sock.read(&mut buf) {
            Ok(n) => n,
            // Timeout e interrupção não são erro: são a chance de reportar em link parado.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                0
            }
            Err(e) => {
                eprintln!("erro de captura: {e}");
                return ExitCode::FAILURE;
            }
        };

        let t = now();
        if n > 0 {
            if parse_ipv4_udp(&buf[..n]).is_none() {
                match classify_other(&buf[..n]) {
                    NotUdp::Ipv6 => n_ipv6 += 1,
                    // Só conta TCP **nas portas SIP**. Contar todo TCP incluiria a
                    // sessão SSH do próprio administrador, e o aviso viraria ruído.
                    NotUdp::Tcp => {
                        if let Some((sp, dp)) = tcp_ports(&buf[..n]) {
                            if args.ports.contains(&sp) || args.ports.contains(&dp) {
                                n_tcp += 1;
                            }
                        }
                    }
                    NotUdp::LaterFragment => n_frag += 1,
                    NotUdp::Other => {}
                }
            }
            if let Some(d) = parse_ipv4_udp(&buf[..n]) {
                let on_port = args.ports.contains(&d.dst_port) || args.ports.contains(&d.src_port);
                if on_port {
                    *seen_ports.entry(d.dst_port).or_insert(0) += 1;
                    let dec = engine.observe(d.src, d.payload, t);
                    // Ruído de perímetro condena a origem: os próximos pacotes dela morrem
                    // no XDP, antes do tap do libpcap, e somem do sngrep.
                    let motivo = match &dec {
                        Decision::Noise { signature } => Some(("user-agent", *signature)),
                        Decision::Injection { pattern } => Some(("injecao", *pattern)),
                        Decision::AuthAbuse { .. } => Some(("forca-bruta", "auth")),
                        _ => None,
                    };
                    if let (Some((tipo, detalhe)), Some(e)) = (motivo, enforcer.as_mut()) {
                        match e.block(d.src, args.block_ttl) {
                            Ok(()) => {
                                println!(
                                    "BLOQUEADO peer={} motivo={tipo} detalhe={detalhe} ttl={}s",
                                    d.src, args.block_ttl
                                );
                                // Auditoria durável: o operador precisa reconstruir a
                                // decisão depois, sem depender de o journal ainda existir.
                                if let Some(s) = db.as_ref() {
                                    s.log_block(t.0, d.src, tipo, detalhe);
                                }
                            }
                            Err(err) => eprintln!("ALARME: não consegui bloquear {}: {err}", d.src),
                        }
                    }
                    if args.debug_unparsed
                        && matches!(&dec, Decision::OutOfScope(r) if *r == "não é SIP")
                    {
                        // Requisito de diagnóstico: "não consegui interpretar" precisa ser
                        // investigável, senão o contador vira ruído que ninguém sabe ler.
                        let n = d.payload.len().min(72);
                        let preview: String = d.payload[..n]
                            .iter()
                            .map(|b| {
                                if b.is_ascii_graphic() || *b == b' ' {
                                    *b as char
                                } else {
                                    '.'
                                }
                            })
                            .collect();
                        println!(
                            "NÃO-SIP peer={} {}:{}->{} len={} [{preview}]",
                            d.src,
                            d.src,
                            d.src_port,
                            d.dst_port,
                            d.payload.len()
                        );
                    }
                    report(&dec, d.src, args.verbose);
                }
            }
        }

        // Lotes do APIBAN, se houver. Não bloqueia: só drena o que já chegou.
        if let (Some(rx), Some(e)) = (apiban_rx.as_ref(), enforcer.as_mut()) {
            while let Ok(batch) = rx.try_recv() {
                let n = batch.ips.len();
                for ip in batch.ips {
                    // Sem expiração: a lista do APIBAN é curada, e reaplicá-la a cada
                    // hora só geraria escrita à toa.
                    let _ = e.block(ip, 0);
                }
                if n > 0 {
                    apiban_total += n as u64;
                    println!("APIBAN: {n} endereços condenados (total {apiban_total})");
                }
            }
        }

        // Checkpoint: durável, nunca no caminho quente (`SPEC.md` §10).
        if let Some(s) = db.as_mut() {
            if t.0.saturating_sub(last_checkpoint) >= args.checkpoint_every.max(30) as u32 {
                last_checkpoint = t.0;
                match s.checkpoint(&engine) {
                    Ok((p, _)) => {
                        // Auditoria com 90 dias — mais que o dobro da janela de
                        // envelhecimento do bitmap, e o suficiente para investigar.
                        s.prune_log(t.0.saturating_sub(90 * 24 * 3600));
                        if args.verbose {
                            println!("    checkpoint: {p} pares gravados");
                        }
                    }
                    Err(e) => eprintln!("ALARME: checkpoint falhou — {e}"),
                }
            }
        }

        if t.0.saturating_sub(last_report) >= args.stats_every.max(1) as u32 {
            last_report = t.0;
            print_stats(&engine, &seen_ports, t, mode);
            if let Some(e) = enforcer.as_ref() {
                if e.has_own_counters() {
                    let c = e.counters();
                    println!(
                        "    XDP: descartados={} vistos={} expirados={} no_mapa={} bloqueados_por_nos={}",
                        c.dropped,
                        c.seen,
                        c.expired,
                        e.blocked_count(),
                        e.blocked_by_us
                    );
                } else {
                    // Mapa de terceiro: o total é majoritariamente dele. Só o que este
                    // processo escreveu pode ser reivindicado como nosso.
                    println!(
                        "    XDP: no_mapa={} (compartilhado) bloqueados_por_nos={}",
                        e.blocked_count(),
                        e.blocked_by_us
                    );
                }
            }
            // Requisito de observabilidade: silêncio é alarme, não normalidade.
            if engine.stats.packets == 0 && !nothing_seen_warned {
                eprintln!(
                    "ALARME: nenhum pacote visto nas portas {:?} em {}s. \
                     Interface errada, porta errada, ou SIP sob TLS?",
                    args.ports, args.stats_every
                );
                nothing_seen_warned = true;
            }
            // Assinatura que nunca casa está podre e o operador precisa saber — foi
            // exatamente o que o fail2ban nunca fez (`SPEC.md` §12).
            if n_ipv6 + n_tcp > 0 {
                println!("    pontos cegos: ipv6={n_ipv6} tcp={n_tcp} fragmentos={n_frag}");
                if !blind_warned {
                    eprintln!(
                        "AVISO: há SIP que este sistema NÃO analisa nas portas {:?} — \
                         IPv6={n_ipv6}, TCP={n_tcp}. Esse tráfego passa sem inspeção \
                         (SIP sobre TLS é cegueira estrutural; ver README).",
                        args.ports
                    );
                    blind_warned = true;
                }
            }
            let total = engine.noise_filter.hits().count();
            if engine.noise_filter.cold_signatures().len() == total
                && engine.stats.sip_parsed > 1000
            {
                eprintln!(
                    "AVISO: nenhuma das {total} assinaturas de user-agent casou em {} \
                     mensagens SIP. Lista possivelmente desatualizada.",
                    engine.stats.sip_parsed
                );
            }
        }
    }
}

fn report(dec: &Decision, peer: Ipv4Addr, verbose: bool) {
    match dec {
        Decision::Block { country, novel_in_window } => println!(
            "BLOQUEIO peer={peer} país={country} inéditos_na_janela={novel_in_window}"
        ),
        Decision::WouldBlock { country, novel_in_window } => println!(
            "BLOQUEARIA (aprendendo) peer={peer} país={country} inéditos_na_janela={novel_in_window}"
        ),
        Decision::Noise { signature } if verbose => {
            println!("ruído peer={peer} assinatura={signature}")
        }
        Decision::Injection { pattern } if verbose => {
            println!("injeção peer={peer} padrão={pattern}")
        }
        Decision::AuthAbuse { attempts } => {
            // Sempre visível: força bruta de credencial é o precursor da Cadeia A.
            println!("FORÇA BRUTA peer={peer} tentativas_autenticadas_na_janela={attempts}")
        }
        Decision::UnknownCountry(digits) => {
            // Sempre visível, mesmo sem -v: é sintoma de plano de discagem errado,
            // e plano errado significa chamada internacional escapando do sistema.
            println!("PAÍS DESCONHECIDO peer={peer} dígitos={digits}")
        }
        Decision::Pass { country, novel } if verbose => {
            println!("passa peer={peer} país={country} inédito={novel}")
        }
        _ => {}
    }
}

fn print_stats(e: &Engine, ports: &BTreeMap<u16, u64>, t: Timestamp, mode: Mode) {
    let s = &e.stats;
    let modo = match mode {
        Mode::Active => "ATIVO".to_string(),
        Mode::Learning { until } => {
            let faltam = until.0.saturating_sub(t.0);
            format!(
                "APRENDENDO (faltam {}d {}h)",
                faltam / 86400,
                (faltam % 86400) / 3600
            )
        }
    };
    println!(
        "--- modo={modo} pacotes={} sip={} respostas={} keepalive={} não_sip={} ruído={} ({}%) injeção={} auth_tent={} auth_abuso={} invites={} intl={} \
         país_desconhecido={} inéditos={} bloqueios={} bloquearia={} peers={} pares={} portas={:?}",
        s.packets,
        s.sip_parsed,
        s.responses,
        s.keepalives,
        s.not_sip,
        s.noise,
        s.noise
            .checked_mul(100)
            .and_then(|n| n.checked_div(s.sip_parsed))
            .unwrap_or(0),
        s.injections,
        s.auth_attempts,
        s.auth_abuse,
        s.invites,
        s.international,
        s.unknown_country,
        s.novel,
        s.blocks,
        s.would_block,
        e.peer_count(),
        e.pair_count(),
        ports
    );
}
