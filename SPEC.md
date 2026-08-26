# TFPS — Especificação de arquitetura

Sistema de prevenção de fraude IRSF para redes SIP. Rust + eBPF, sem configuração de política, offline, open source.

Este documento é o **destino** do mapa em `.scratch/tfps-next/`. Ele consolida treze decisões travadas; cada uma tem um ticket com a justificativa completa, referenciado ao lado. Aqui está o **o quê**, não o **porquê** — vá ao ticket quando precisar do segundo. O vocabulário está em `CONTEXT.md` e é normativo.

---

## 1. O que o sistema é

Um binário Rust que roda **no host do softswitch**, observa o tráfego SIP por captura de pacote, aprende o comportamento normal de cada origem, e bloqueia chamadas internacionais anômalas em tempo real.

**O que ele não é**: não é proxy, não é B2BUA, não fala SIP além de forjar respostas, não tem nuvem, não consulta serviço externo para decidir, não tem lista de fraude, não tem modelo estatístico.

**O caso que ele existe para resolver**: o **PBX comprometido a jusante** — aquele em que o atacante já tem credencial válida, o tráfego chega autenticado do IP de sempre, e todo sinal de perímetro está limpo. É onde `fail2ban` e APIBAN são estruturalmente cegos: o primeiro conta falhas de autenticação que não acontecem, o segundo consulta reputação de um IP que é o do próprio cliente.

**Alvo de escala**: wholesale. `[ticket 11]`

---

## 2. Topologia e implantação `[ticket 06]`

- **No próprio host do softswitch.** Bump-in-the-wire e porta espelhada estão fora de escopo.
- **Captura sem bind.** XDP e/ou `AF_PACKET` engatam no netdev e **não abrem o socket UDP**. O softswitch mantém o bind dele; não há conflito de porta e nada precisa ser reconfigurado no que já roda.
- **Modo promíscuo não é necessário** — o tráfego já é endereçado ao host.
- **Portas capturadas são declaradas**, padrão `5060/UDP`, múltiplas aceitas (requisito de wholesale, onde 5060/5080/5061 convivem). Um mapa de portas consultado pelo programa XDP.
- **Piso de kernel: ≥ 5.15**, ideal ≥ 6.2. Verificar RHEL/Rocky/Alma 9, que shipa 5.14 com backports.
- **Ferramental: `aya`.** `redbpf` está arquivado desde 2023.

### Fail-open, estrutural

**O programa eBPF não é fixado no bpffs.** Sem pin, o refcount cai quando o processo carregador morre e o kernel desanexa sozinho — fail-open **por construção**, não por código de tratamento de erro que pode ter bug.

Telefonia parada é pior que fraude passando. Mas o sistema **grita** quando para.

---

## 3. O caminho de um INVITE

```
pacote na porta capturada
   │
   ├─ perímetro (XDP) ──── é ruído conhecido? ──► XDP_DROP, silêncio total
   │                        (user-agent, IP, taxa)      [nunca responde]
   │
   ├─ evento para userspace via ring buffer (sempre, mesmo quando dropado)
   │
   └─ userspace Rust
        │
        ├─ casa algum prefixo internacional declarado do peer?
        │     └─ NÃO ──► fora de escopo, passa. Fim.        ◄── filtro mais barato
        │
        ├─ despela prefixo, canonicaliza (libphonenumber), resolve país
        │
        ├─ modo de aprendizado ativo? ──► registra, não bloqueia
        │
        └─ país inédito para o par (peer, A-number)?
              │
              ├─ NÃO ──► passa
              └─ SIM ──► conta inéditos do par na janela de 1h
                          │
                          ├─ < N ──► passa
                          └─ ≥ N ──► XDP_DROP do INVITE
                                     + userspace forja 603 Decline
```

**Duas propriedades desse fluxo:**

O **filtro de prefixo vem antes de tudo** e é a operação mais barata que existe. Numa operadora de tráfego majoritariamente doméstico, a maioria das chamadas sai por ali sem canonicalizar. **O custo do sistema escala com o volume internacional, não com o total.**

O **caminho de decisão não tem estado de diálogo**. `[ticket 09]` Duração e desfecho são pós-fato e pertencem ao caminho de aprendizado, que é assíncrono e **pode perder eventos sem comprometer a proteção**.

---

## 4. Canonicalização `[ticket 12]`

**Por que é crítico**: 20,3% dos destinos do corpus de produção não resolvem a país sem despelamento — e país é a **única** feature comportamental que sobreviveu à medição. Errar aqui não degrada uma feature secundária; degrada a única que existe.

**Lista de prefixos internacionais por central**, declarada, com **casamento pelo mais longo**:

```json
{ "peers": { "10.0.0.5": { "intl_prefixes": ["+", "011", "9011", "00", ""] } } }
```

Entrada vazia `""` = peer manda E.164 puro, comum em wholesale.

Casamento pelo mais longo resolve a ambiguidade clássica sozinho: central com `0` para tronco nacional e `00` para internacional produz `0212…` nacional e `00212…` internacional.

**Validação: `libphonenumber`** — Apache-2.0 **inclusive nos metadados**, portanto embarcável. E `isValidNumber` **não é checagem de formato: é afirmação sobre faixa alocada** (*"a valid number range is one from which numbers can be freely assigned by carriers to users"*), reproduzindo a base comercial do paper NDSS (72,3%/27,7% contra 70,0%/30,0%).

### Declara, aprende em paralelo, reclama quando discordar — **requisito, não refinamento**

O erro é **assimétrico**:

| erro | efeito |
|---|---|
| prefixo a mais | inofensivo — não canonicaliza para país válido, cai fora sozinho |
| **prefixo faltando** | **grave e silencioso** — a chamada internacional escapa do sistema inteiro e nada acusa |

O segundo é o modo de falha do `fail2ban` que este projeto usa como diferencial. Portanto: o aprendizado de plano de discagem roda sempre, em segundo plano, e **grita** se vir tráfego com cara de internacional sob prefixo fora da lista.

### O que não canonicaliza nunca é bloqueado

**IRSF é, por definição, internacional.** Ramal interno, código de serviço, número curto, URI SIP — se não resolve para E.164 internacional, **não é assunto do sistema e passa**. Não é falha; é fora de escopo.

Bloquear por falha de canonicalização seria repetir o **R07** do TFPS Java, que negava tudo que não conseguia classificar e virou **39% de todas as rejeições** — a maior fonte de bloqueio era ignorância, não detecção.

"Não canonicalizável" é **categoria própria de novidade**: peer que sempre manda número limpo e passa a mandar lixo é anômalo.

---

## 5. Unidade de aprendizado `[ticket 09]`

**Chave hierárquica `(peer, A-number)`.**

A chave confiável e a chave útil são opostas. O **A-number é forjável** — campo de texto no `From`. O **IP do peer não é**: sobre UDP daria para falsificar, mas a resposta SIP não voltaria e a chamada não completaria. Só que o peer é a entidade de **perfil largo**, que satura todos os sinais comportamentais.

Ancorando no peer e agrupando por A-number, **a forjabilidade vira sinal**:

- quem **rotaciona** A-numbers faz explodir a cardinalidade de A-numbers novos naquele peer — detectado um nível acima;
- quem **reusa** um A-number faz aquele par acumular histórico e cai na novidade normal.

Nas duas saídas o atacante perde. É isto que torna wholesale tratável: a operadora tem perfil largo, **cada par tem perfil estreito**.

---

## 6. O sinal `[ticket 10]`

**Não há modelo estatístico.** Sem Isolation Forest, sem Random Forest, sem z-score, sem binomial negativa. Só **detecção de novidade** — pertinência a conjunto.

### Estruturas

| estrutura | onde | tamanho | conteúdo |
|---|---|---|---|
| **bitmap girante** | por par `(peer, A-number)` | **64 bytes** | dois bitmaps de 256 bits: países vistos no período atual e no anterior |
| **distribuição de frequência** | por peer | ~200 contadores | quantas chamadas por país — o prior |
| plano de discagem | por peer | pequeno | prefixos declarados + aprendidos |

Um milhão de pares ≈ **64 MB**. O bitmap é **exato**, sem sketch e sem falso positivo — possível só porque o alfabeto tem ~200 países.

### Predicado de bloqueio

> **Contagem de países inéditos para o par, dentro de uma janela de 1 hora, ≥ N.**

- **Janela = 1 hora** — constante universal, derivada da física da fraude: segundos são a escala do flood de sinalização, dias diluem o episódio.
- **N = 10** — constante universal na v1. Disparou **4 vezes em 2.829 conta-dias** na medição, e as quatro janelas eram as mais atípicas do corpus.

**Um país inédito sozinho não dispara**: estreia de país acontece em **0,85% das chamadas** após aquecimento (0,28% na unidade madura). Bloquear isso seria catástrofe. O sinal é **acúmulo**.

As duas constantes são **universais, não por cliente**. A espécie de número que matou o TFPS 2023 era a per-cliente que ninguém ajustava.

### Prior do par novo

Herdar o conjunto **inteiro** de países do peer não funcionaria — peer wholesale liga para 200 países e a saturação voltaria.

- **par maduro** → o país está no bitmap dele? consulta exata;
- **par novo** → quão comum é esse país **para o peer**? comum não surpreende; raro surpreende, mesmo sem histórico próprio.

O peso migra continuamente do peer para o par. É encolhimento hierárquico (**Rubin, 1981**), e o prior sai das **unidades paralelas da própria instalação** — nenhuma nuvem necessária.

### Envelhecimento

A cada `T` = **45 dias**: descarta o bitmap anterior, promove o atual, zera o novo. Memória efetiva de 45 a 90 dias. `T` precisa ser maior que o modo de aprendizado.

**Efeito que resolve o bootstrap envenenado**: se o PBX chegou comprometido e o aprendizado absorveu a fraude, os países envenenados **envelhecem e saem sozinhos — o sistema se cura**.

### Features da v1, lista fechada

País de destino, hora do dia em **24 categorias aprendidas** (a evidência dos dois papers é que isso bate qualquer noção de "horário comercial" — AUC 0,96 contra 0,92 — e "fraude é de madrugada" é propriedade de dataset, não do fenômeno), peer, A-number. Do caminho de aprendizado: duração e desfecho.

**Fora, com o motivo**: novidade de faixa (exigiria sketches para sustentar aposta não medida); distância até test IPRN, dígito de dispersão, `IRSF likelihood` (exigem corpus); `Test call ratio` e `spreadness` (exigem logs de chamada de teste inexistentes); rajada e razão de fan-out (**refutadas por medição** — ver `CONTEXT.md`).

---

## 7. Perímetro

**Não existe para pegar fraude. Existe para impedir que lixo contamine a linha de base comportamental.** Se tráfego de scanner alimenta o baseline de um par, o modelo aprende que rajada para destino estranho é normal ali, e a defesa se envenena sozinha.

Fontes: lista de user-agents e faixas de IP no JSON; taxa; opcionalmente APIBAN. Ativo **desde a instalação**, sem esperar aprendizado.

**Observar e dropar acontecem no mesmo programa XDP** — o evento vai ao ring buffer **antes** do `XDP_DROP`, para que o silêncio não cegue o próprio sensor.

---

## 8. Imposição `[ticket 07]`

**Dois vereditos na v1: bloqueia ou passa.** Sem desafio.

| caso | eBPF | userspace |
|---|---|---|
| scanner / perímetro | dropa | **nada — silêncio total** |
| fraude, cliente legítimo | dropa | forja `603 Decline` |
| limpo | passa | nada |

### O perímetro cala, a fraude fala

Qualquer resposta a scanner — `403`, `404`, mesmo `401` — confirma endpoint SIP vivo e convida escalada; respostas diferenciadas ainda vazam enumeração de ramal. Mas dropar em silêncio um **cliente legítimo** custa 32 segundos de retransmissão pelos timers A/B da RFC 3261, e o caso central do produto é um cliente pagante, onde silêncio parece pane.

**Exceção**: **iscas respondem deliberadamente.** Silêncio protege superfície de produção; resposta alimenta a armadilha. Superfícies diferentes, papéis diferentes.

### Drop-then-forge

O XDP **dropa** o INVITE e o userspace **forja** a resposta via raw socket (`CAP_NET_RAW`). Isso **elimina a corrida** contra o softswitch em vez de tentar vencê-la. A RFC 3261 §17.1.3 torna a forja mecânica: a resposta reusa `Via`/`branch`, `From` tag, `Call-ID` e `CSeq` do próprio INVITE — só é preciso gerar `To-tag` e `Contact`.

**eBPF não consegue criar pacote do zero** — nenhum helper monta frame novo, só reescreve ou redireciona. Por isso a forja é de userspace.

---

## 9. Ciclo de vida

**Camadas com datas de ativação diferentes:**

| camada | ativa em |
|---|---|
| perímetro | minuto 1 |
| comportamento | **dia 31** |

Durante os 30 dias a camada comportamental **observa e não bloqueia**, e o sistema **anuncia isso o tempo todo**. Aquecimento de novidade estabiliza em 7 dias; 30 é conservador.

**Dia 31 é a única interação humana do produto** — confirmação, não configuração:

> *"Nestes 30 dias vi tráfego para estes N países, com este padrão. Ativar a proteção com esta linha de base?"*

É a defesa contra o PBX que chegou já comprometido. Uma pergunta na vida do produto não é configuração contínua. Custo registrado: é fricção, e fricção foi identificada como causa de morte do TFPS 2023 — se a produção mostrar que derruba adoção, a alternativa é ativar automaticamente e **oferecer** a revisão em vez de exigi-la.

---

## 10. Persistência `[ticket 06]`

**SQLite. Um arquivo.** Sem servidor, sem daemon, sem credencial, sem porta.

Duas razões além da simplicidade: é zero configuração de verdade — o TFPS 2023 tinha senha de MySQL em texto claro em seis pontos do `.cfg` gerado; e **o operador consegue abrir e ver o que o sistema aprendeu**, o que num produto silencioso por design separa "confio nisso" de "não sei se está funcionando". Precedente: o SentryPeer faz igual.

**É armazenamento durável, não caminho quente.** Conjunto de trabalho em memória, carga no boot, checkpoint periódico. Consultar SQL por INVITE seria gargalo de escrita em wholesale.

**Divisão de estado**: o de **perímetro** morre com o processo e se reconstrói em minutos do próprio tráfego — coerente com o fail-open por não-pin. O **comportamental**, de 45 a 90 dias, sobrevive em disco.

O log de auditoria de bloqueios vai direto para lá, por ser volume baixo.

---

## 11. Configuração

**Nada é obrigatório.** Um JSON opcional, que acompanha o produto:

| campo | categoria | obrigatório |
|---|---|---|
| portas capturadas | instalação | não (padrão `5060/UDP`) |
| prefixos internacionais por peer | instalação | não (aprendido em paralelo) |
| user-agents e faixas de IP de ruído | dado do produto | não |
| chave APIBAN | integração opcional | não |
| regex estrutural por operação | override | não, **vazio por padrão** |

**Distinção normativa**: configuração de **instalação** diz ao sistema *onde olhar e como ler*; configuração de **política** diria *o que é fraude*. A primeira é admitida, a segunda **não existe neste produto**. Os catorze botões do `defines.m4` do TFPS 2023 não têm equivalente aqui.

**O regex de override** serve a regra estrutural específica da operação (*"nosso tráfego nunca vai para satélite"*), **não** a whitelist de destino — esta última é o R07 com outra sintaxe. Se preenchido, o sistema **reporta a taxa de disparo de cada padrão**: regex que casa zero vezes em três meses está podre e o usuário precisa saber.

**APIBAN**, se configurado: sincronização em **segundo plano** pela API incremental, alimentando mapa local. **Jamais consulta por INVITE** — foi o gargalo fatal de 2023 (`rest_get()` síncrono sem cache, teto de ~26 INVITEs/s, terceiro indisponível congelava tudo). O sistema opera com lista velha se a rede cair.

---

## 12. Observabilidade — requisitos, não recursos

O diferencial declarado do projeto contra o `fail2ban` é que **o incumbente falha em silêncio e você não descobre**. Três fatos sustentam isso: o canal de segurança do Asterisk vem desligado por padrão, então a `failregex` nº 6 nunca casa numa instalação padrão; o PJSIP não loga abaixo de 5 requisições em 5 s, criando taxa de ataque invisível por construção; e nenhuma versão do fail2ban jamais alertou sobre filtro que casa zero linhas.

**Este sistema não pode repetir isso.** São requisitos:

1. **Alarme de silêncio.** Se parar de ver tráfego, parar de disparar por completo, ou não conseguir canonicalizar nada — **grita**.
2. **Discordância de plano de discagem.** Tráfego internacional sob prefixo não declarado — **grita**.
3. **Taxa de disparo como termômetro.** Referência: 0,85% de chamadas com estreia de país após aquecimento, 0,28% na unidade madura. Muito acima é ataque **ou** modelo quebrado; muito abaixo é cegueira.
4. **Regex e listas que casam zero** — reporta.
5. **Todo bloqueio registra o porquê**, legível: qual unidade, qual país, quando foi a última vez que aquela unidade ligou para lá.
6. **Desbloqueio manual é o proxy de precisão.** Sem rótulo, é a única medida disponível: se o operador nunca desbloqueia, a precisão provavelmente está boa.
7. **O modo em que está** — aprendizado ou ativo — visível o tempo todo.

### O primeiro sucesso do usuário

**O sngrep limpo.** Pacote dropado no XDP nunca vira `sk_buff` e portanto **não aparece no sngrep, tcpdump ou tshark** — libpcap engata no `AF_PACKET`, no nível do netdev, depois do XDP. O usuário instala, abre o sngrep, e o lixo sumiu. Não precisa haver fraude, o modelo não precisa disparar, não precisa painel.

Isto é o gancho de retenção do produto e **discrimina contra o nftables**, cujo drop acontece depois do tap do `AF_PACKET` e continuaria poluindo a captura.

Estimativa do dev **a medir e não presumir**: ~90% do ruído removido por user-agent, +9% por falha de autenticação, ~99% total com APIBAN. `[ticket 17]`

---

## 13. Fora de escopo, e limitações conhecidas

O projeto **não faz promessa a quem baixa**. Limitação conhecida é **documentada, não resolvida em engenharia**.

| limitação | natureza |
|---|---|
| **Cliente de perfil internacional largo** | novidade, fan-out e taxa **saturam por construção**; nenhum sinal comportamental dispara. Minoria dos clientes, maioria do prejuízo. |
| **SIP sobre TLS** | cegueira criptográfica no conteúdo. Só metadados. Imposição por reputação de IP ainda funciona. |
| **SIP sobre TCP** | reassembly L7 dentro do XDP é inviável; delegar a userspace ou não suportar na v1. |
| **30 dias sem bloqueio comportamental** | por desenho, anunciado. |
| **PBX já comprometido na instalação** | duas defesas parciais: confirmação do dia 31 e envelhecimento do bitmap. |
| **Cadeia B** (credencial furtada via provisionamento) | precursor está em HTTP, fora do SIP. `[ticket 13]` |

**Fora de escopo por decisão**: Wangiri; fraude de assinatura e SIM box; reescrever pilha SIP; bump-in-the-wire e porta espelhada; corpus de números de fraude; nuvem; desafio por captcha.

---

## 14. Diferido para a produção

Nada disto bloqueia a v1. Tudo se decide com dado, não com discussão.

- **Predicado relativo ao peer** em vez de `N` universal — calibra contra a medição do ticket 17.
- **SPRT / Threshold Random Walk** — evidência por chamada em vez de por janela. Sem precedente em telecom.
- **Novidade de faixa** — só se a medição justificar o custo de sketches.
- **Variação de formato como sinal** — cai de graça do plano de discagem aprendido; medir antes de construir.
- **Estrangulamento de concorrência e corte de duração** — se a produção revelar um meio ambíguo que hoje não se antevê.
- **Honeypot local**, **telemetria colaborativa**, **cadeia de precursores**. `[tickets 13, 14, 16]`
- **Empacotamento, licença, piso de kernel verificado.** `[ticket 15]`

---

## 15. O princípio que amarra tudo

O TFPS 2023 foi uma boa tentativa. **Se os parâmetros fossem dinâmicos, teria funcionado** — o `params_training.sql` já calculava µ+2σ por conta sobre 90 dias, mas **nunca aplicava**, e as quatro colunas que lia não existiam na tabela. O `TODO-LIST` tinha duas linhas, uma delas `Auto-Training`.

O que matou foi **fricção** e **falta de foco** — e a segunda é mensurável na auditoria: `globalblacklist` com 18.033 números carregados e nunca consultada; `ip_blacklist` com 2.129 IPs sem consumidor; `countries.risk` para 231 países sem consumidor; z-score comentado; STIR/SHAKEN comentado; quota diária inalcançável por um `route()` fora do `if`.

**Máquina pela metade em toda parte.**

Este spec corta corpus, nuvem, modelo estatístico, desafio, novidade de faixa e coletor de telemetria — não por modéstia, mas porque **um sistema sem modelo não tem modelo pela metade**.
