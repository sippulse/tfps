# TFPS

**Telephony Fraud Prevention System** — prevenção de fraude IRSF em redes SIP.

Observa o tráfego no fio, aprende o comportamento normal de cada origem, e descarta o lixo
no kernel antes que ele chegue ao seu `sngrep`.

Sem configuração de política. Sem nuvem. Sem lista de fraude. Um binário estático.

---

## O lixo some do sngrep

Esta é a propriedade que o produto entrega, e ela depende de uma ordem específica dentro
do kernel Linux:

```
NIC → driver → XDP ← o TFPS descarta aqui
                 ↓
            sk_buff → ptype_all ← o libpcap engata aqui (sngrep, tcpdump, tshark)
                        ↓
                    netfilter ← iptables e nftables agem aqui
```

Pacote descartado no **XDP nunca chega ao tap do libpcap**. É por isso que `nftables` não
serviria para este fim: o drop dele acontece depois, e a captura continuaria poluída.

**Verificado em produção**: com 959 origens bloqueadas, 40 segundos de `tcpdump` filtrando
seis delas capturaram **zero** pacotes, contra 5 no controle no mesmo intervalo.

Não é hermético — um pacote passou em 90 s num teste. O que os dados sustentam é redução
drástica, não bloqueio perfeito.

---

## Estado — v0.1.0

| pronto | falta |
|---|---|
| captura `AF_PACKET`, sem bind de porta | forja de `603` para o veredito de fraude |
| imposição por XDP (nativo ou genérico) | prior do peer para par novo |
| perímetro: user-agent, injeção, força bruta | aprendizado do plano de discagem |
| integração opcional com APIBAN | duração da chamada via `BYE` |
| parse de SIP: requisição, resposta, keepalive | honeypot local |
| plano de discagem por lista de prefixos | IPv6 e SIP sobre TCP |
| país de destino (240 códigos E.164) | confirmação do dia 31 |
| novidade por par, com bitmap girante | |
| persistência em SQLite | |
| tetos de memória com poda automática | |

**Hoje ele filtra ruído e aprende. Ainda não bloqueia fraude** — a camada comportamental
observa por 30 dias antes de agir, e o veredito de fraude ainda não é imposto.

---

## Como ele decide

```
pacote na porta observada
   │
   ├─ user-agent de scanner conhecido? ──► condena a origem, some do sngrep
   ├─ injeção na URI (' -- %27 ?=?)?  ──► condena a origem, some do sngrep
   ├─ força bruta de credencial?       ──► condena a origem, some do sngrep
   │
   ├─ casa algum prefixo internacional? ──► NÃO: fora de escopo, passa. Fim.
   │                                         (é por aqui que sai a maioria do tráfego)
   ├─ despela, canonicaliza, resolve país
   │
   └─ país inédito para este par (peer, A-number)?
         ├─ NÃO ──► passa
         └─ SIM ──► quantos inéditos na última hora?
                      ├─ < 10 ──► passa
                      └─ ≥ 10 ──► bloqueia
```

**Um país inédito sozinho nunca dispara.** Estreia de país acontece em 0,85% das chamadas;
bloquear isso seria bloquear 0,85% do tráfego internacional de todo mundo. O sinal é
**acúmulo**, não evento — dez países inéditos numa hora dispararam 4 vezes em 2.829
conta-dias na medição que originou a regra.

### O perímetro não existe para pegar fraude

Ele existe para **impedir que lixo contamine a linha de base comportamental**. Se varredura
alimenta o baseline de uma conta, o modelo aprende que rajada para destino estranho é
normal ali, e a defesa se envenena sozinha.

Duas famílias, com confianças diferentes:

- **User-agent de ferramenta** (18 assinaturas: `sipcli`, `friendly`, `sipvicious`,
  `pplsip`, `sipscan`, `Nmap NSE`…). Fraco como *detecção* — atacante competente forja UA
  legítimo. Adequado como **filtro de volume**, porque scanner preguiçoso com UA padrão é
  a maioria dos pacotes.
- **Injeção na URI** (`'`, `%27`, `--`, `%24`, `%60`, `==`, `?=?`, `union`, `select`, e `;`
  na parte de usuário). Confiança **mais alta**: nenhum telefone real põe aspa simples no
  `From`.
- **Força bruta de credencial** — 20 tentativas autenticadas em 60 s.

### O que *não* se conta como força bruta

**`401` cru não é sinal de nada.** O desafio digest é o fluxo normal: todo `REGISTER`
legítimo recebe um `401` com nonce antes de reenviar com `Authorization`. Contar desafios
bloquearia todos os seus clientes no primeiro minuto.

O que se conta é **`REGISTER` carregando `Authorization`** — uma tentativa de senha. Um
telefone legítimo manda uma por ciclo de registro (tipicamente a cada 300 s); quem testa
credencial manda muitas por segundo. Nenhuma correlação de resposta, nenhum estado de
diálogo.

Medido no servidor de referência: **2 desafios em 45 s** de tráfego legítimo. O limiar de
20/min dá ~7× de folga. **Ressalva**: NAT grande agrega muitos telefones num IP e pode
encostar no limiar — é a mesma limitação do `fail2ban`, e é por isso que o bloqueio é
temporário.

---

## Configuração — `/etc/tfps/config.json`

**Todo campo é opcional e o sistema funciona sem o arquivo.** O que está aqui é
configuração de **instalação** — onde olhar, como ler os números — e integração opcional.
Nunca configuração de **política**, que diria o que é fraude: os catorze botões do
`defines.m4` do TFPS de 2023 não têm equivalente.

```json
{
  "ports": [5060, 5061],
  "intl_prefixes": ["+", "00", "011", "9011"],

  "peers": {
    "10.0.0.5":  { "intl_prefixes": ["9011", "011"] },
    "203.0.113.7": { "bare_e164": true }
  },

  "signatures": ["MeuScannerLocal", "=sipsak"],
  "injection": ["xp_cmdshell"],

  "apiban_key": "sua-chave-opcional",

  "learn_days": 30,
  "block_ttl": 3600,
  "stats_every": 120,
  "checkpoint_every": 300,
  "iface": "eth0",
  "db": "/var/lib/tfps/tfps.db"
}
```

Precedência: **linha de comando > arquivo > padrão embutido**. Assim dá para depurar em
produção sem editar arquivo.

Um **campo desconhecido é erro**, não silêncio: um `apiban_kei` ignorado faria você
acreditar que ligou o APIBAN quando não ligou. O mesmo vale para JSON quebrado e para IP
de peer inválido — tudo vira alarme no arranque.

### `peers` — o plano de discagem por central

Declarar bate aprender porque vale já na **primeira** chamada daquele peer, em vez de
esperar convergência. E o peso é grande: **20,3% dos destinos não resolvem a país** sem
despelamento correto, e país é a única feature comportamental que sobreviveu à medição.

`bare_e164` diz que a central manda E.164 puro, sem prefixo — comum em wholesale. É um
campo explícito e não um prefixo vazio, porque a semântica é perigosa: com ele ligado,
`2125551234` é Marrocos; sem ele, é um número nacional dos EUA.

O aprendizado do plano continua rodando em paralelo, e discordância vira alarme.

### `signatures` e `injection` — acrescentam, nunca substituem

Os seeds vêm **embutidos no binário** e funcionam sem arquivo nenhum. O que você lista
**soma** aos 18 user-agents e 11 padrões de fábrica.

Substituir faria quem escreve três linhas perder os embutidos sem perceber — downgrade
silencioso, que é exatamente a falha que este projeto condena. Prefixo por padrão; `=texto`
casa exato (o equivalente a `^…$`).

O arranque mostra quantas vieram de cada lado, e o sistema avisa quando nenhuma assinatura
casa depois de milhares de mensagens: assinatura que nunca dispara está podre.

### `apiban_key` — integração opcional

Lista colaborativa do [APIBAN](https://apiban.org), alimentada por honeypots. Roda em
**thread separada** e entrega por canal: HTTP nunca toca o caminho do pacote.

Foi exatamente aí que o TFPS de 2023 morreu — um `rest_get()` **síncrono por INVITE**, sem
cache, com 4 workers: teto de ~26 INVITEs/s, e qualquer indisponibilidade do apiban.org
congelava a decisão de todas as chamadas. Aqui, se a rede cair, o sistema segue com a lista
que já tem.

---

## Compilar

```sh
cargo test                                                   # 66 testes
cargo build --release --target x86_64-unknown-linux-musl
```

O alvo musl produz um **estático de ~2,7 MB**, sem dependência de glibc — roda em Debian
12, Ubuntu 24.04 e no que vier. Isso resolveu um caso real: a máquina de build tinha glibc
2.39 e o servidor 2.36, e glibc não é compatível para frente.

O SQLite é compilado junto, o que exige um compilador C que saiba gerar para musl. Se você
não tiver `musl-tools`, o [zig](https://ziglang.org) serve e não precisa de root:

```sh
export CC_x86_64_unknown_linux_musl="zig cc -target x86_64-linux-musl"
export AR_x86_64_unknown_linux_musl="zig ar"
```

### O programa XDP

Escrito em C (`ebpf/tfps_xdp.c`) porque só o lado kernel precisa de LLVM — mantê-lo em C
dispensa o `bpf-linker` na máquina de desenvolvimento. Compile no alvo:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c tfps_xdp.c -o /usr/local/lib/tfps/tfps_xdp.o
```

Requer kernel **≥ 5.15** com BTF. Testado em 6.1.

---

## Instalar e rodar

```sh
scp target/x86_64-unknown-linux-musl/release/tfps root@servidor:/usr/local/bin/
tfps
```

Sem argumento nenhum ele já funciona, com os padrões embutidos. Para ajustar à sua
instalação, escreva `/etc/tfps/config.json` — ver a seção de configuração abaixo.

A captura é `AF_PACKET`/`SOCK_DGRAM`: engata no netdev e **não abre socket UDP**, então o
softswitch mantém o bind dele e não percebe nada. Nada precisa ser reconfigurado.

Precisa de `CAP_NET_RAW` (captura), `CAP_BPF` e `CAP_NET_ADMIN` (XDP).

| opção | efeito |
|---|---|
| `--ports 5060,5080` | portas SIP a observar (padrão `5060`) |
| `--intl +,00,011,9011` | prefixos de discagem internacional |
| `--learn-days N` | dias observando sem bloquear fraude (padrão `30`) |
| `--active` | pula o aprendizado |
| `--iface eth0` | interface do XDP (padrão: a da rota default) |
| `--xdp-obj PATH` | objeto BPF (padrão `/usr/local/lib/tfps/tfps_xdp.o`) |
| `--drop-map PATH` | usar um mapa de drop já fixado por outro produto |
| `--block-ttl N` | segundos de bloqueio (padrão `3600`; `0` = sem expirar) |
| `--no-enforce` | só observa, não toca em XDP |
| `--db PATH` | base SQLite (padrão `/var/lib/tfps/tfps.db`) |
| `--no-db` | não persiste — o aprendizado morre no restart |
| `--signatures PATH` | arquivo extra de assinaturas (além do `config.json`) |
| `--apiban-key KEY` | integra o APIBAN, em segundo plano |
| `--config PATH` | configuração (padrão `/etc/tfps/config.json`) |
| `--stats-every N` | segundos entre relatórios (padrão `60`) |
| `-v` | imprime cada tentativa internacional |
| `--debug-unparsed` | mostra o payload que não parseou |

### Convivendo com quem já ocupa o hook

Só cabe **um** programa XDP por interface. Se já houver um mapa de drop fixado, aponte
`--drop-map` para ele e o TFPS escreve nesse mapa em vez de disputar o hook.

**Cuidado com o raio de dano**: o programa do TFPS descarta apenas as portas SIP, para que
um IP atrás de CGNAT não perca web e SSH por causa de um scanner que divide o endereço. Um
mapa de terceiro pode ter política mais ampla, e nesse caso o raio de dano passa a ser o
dele.

---

## Ler o relatório

```
--- modo=APRENDENDO (faltam 29d 23h) pacotes=330 sip=98 respostas=0 keepalive=232
    não_sip=0 ruído=12 (12%) injeção=0 invites=62 intl=62 país_desconhecido=20
    inéditos=21 bloqueios=0 bloquearia=0 peers=3 pares=14 portas={5060: 330}
    auth_tent=142 auth_abuso=1
    XDP: descartados=1840 vistos=2100 expirados=3 no_mapa=7 bloqueados_por_nos=7
```

| campo | o que significa |
|---|---|
| `modo` | aprendendo (não bloqueia fraude) ou ativo |
| `keepalive` | pings CRLF de NAT (RFC 5626) — numa 5060 residencial são a maioria |
| `não_sip` | sem classificação. **Deveria ser ~0**; alto significa algo não entendido |
| `ruído (%)` | quanto o perímetro removeu — o número que mede o sngrep limpo |
| `país_desconhecido` | internacional pela forma, sem país reconhecível: sintoma de plano de discagem errado, e na prática também pega evasão por padding de prefixo |
| `inéditos` | estreias de país; a referência medida é 0,85% das chamadas |
| `bloquearia` | teria bloqueado se não estivesse aprendendo |
| `auth_tent` | tentativas autenticadas observadas (o denominador da força bruta) |
| `auth_abuso` | origens condenadas por força bruta |
| `bloqueados_por_nos` | origens que **este** processo condenou |

### Silêncio é alarme, não normalidade

O argumento deste projeto contra o `fail2ban` é que **o incumbente falha em silêncio** — o
canal de segurança do Asterisk vem desligado por padrão, o PJSIP não loga abaixo de 5
requisições em 5 s, e nenhuma versão jamais alertou sobre um filtro que casa zero linhas.

Repetir isso perderia o diferencial. Então o TFPS reclama quando:

- para de ver tráfego nas portas observadas;
- vê SIP por caminhos que não analisa (IPv6, TCP);
- não consegue carregar ou anexar o XDP — e diz que **não vai bloquear nada**;
- não consegue persistir — e diz que o aprendizado morrerá no restart;
- nenhuma assinatura de user-agent casa depois de milhares de mensagens.

---

## Persistência

Um arquivo SQLite. Sem servidor, sem daemon, sem credencial, sem porta.

```sh
sqlite3 /var/lib/tfps/tfps.db "select * from block_log order by ts desc limit 20"
```

Guarda o bitmap de países por par, a frequência de países por peer, o log de bloqueios, e
— o que mais importa — **quando o aprendizado começou**. Sem isso, cada restart reiniciaria
os 30 dias e a contagem regressiva prometeria algo que um `systemctl restart` apagaria.

É armazenamento **durável, não caminho quente**: o conjunto de trabalho vive em memória,
com carga no boot e checkpoint a cada 5 minutos. Consultar SQL por INVITE seria gargalo.

---

## Limites de memória

Rotacionar A-number é comportamento esperado do atacante. Sem teto, o sistema responderia
alocando até morrer — um vetor de negação de serviço descrito na própria especificação.

Tetos de **50 mil pares por peer** e **10 mil peers**. Ao encher, o sistema poda os pares
não vistos na última hora: a assinatura da rotação é aparecer uma vez e nunca mais, então
os efêmeros saem e quem volta permanece.

---

## O que ele não faz

**Não bloqueia por falha de canonicalização.** Foi o `R07` do TFPS de 2014, que negava tudo
o que não conseguia classificar e virou 39% de todas as rejeições — a maior fonte de
bloqueio do sistema era ignorância, não detecção. Ramal interno, código de serviço e URI
SIP não são assunto deste sistema e passam.

**Não vê SIP sobre TLS.** Cegueira criptográfica, sem contorno. A imposição por reputação
de IP continua funcionando, porque metadados permanecem visíveis.

**Não vê IPv6 nem SIP sobre TCP** — mas avisa quando eles aparecem.

**Não cobre cliente de perfil internacional largo.** Contra quem já liga para dezenas de
países todo dia, a novidade satura por construção e nenhum sinal comportamental dispara.

**Sem promessa a quem baixar.**

---

## Documentação

- [`SPEC.md`](SPEC.md) — a arquitetura e as decisões, com o porquê de cada uma
- [`CONTEXT.md`](CONTEXT.md) — o vocabulário, normativo para o código e a documentação

## Licença

Apache-2.0.
