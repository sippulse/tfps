# CONTEXT

Vocabulário do TFPS. Um termo, um significado, em todo o sistema.

Este arquivo existe por uma razão concreta: no TFPS 2023, `off_hours` significava *"fora de 09:00–17:00 Seg–Sex"* no proxy e *"fim de semana"* no cron de estatísticas. As duas definições nunca bateram, e nenhuma das duas estava errada isoladamente. Termo ambíguo é bug silencioso.

Glossário apenas. Nada de decisão de implementação.

---

## Tráfego e chamada

**Tentativa de chamada** — um `INVITE` observado. É a unidade sobre a qual se decide. Existe antes de qualquer resposta e independe de a chamada completar.

**Chamada** — uma tentativa que foi atendida (`200 OK`). Só existe em retrospecto. **Não é sinônimo de tentativa**, e a distinção importa: o veredito é dado sobre uma *tentativa*, enquanto duração e desfecho pertencem a uma *chamada*.

**Diálogo** — a sequência `INVITE` → resposta → `BYE` de uma mesma conversa, correlacionada por `Call-ID` e tags. Reconstruído a partir de pacotes observados, nunca consultado de um banco do softswitch.

**Duração** — segundos entre o `200 OK` e o `BYE`. Dado **pós-chamada**: alimenta o aprendizado, jamais a decisão.

---

## Identidades

**A-number** — o número de origem da tentativa, extraído do `From`. **É forjável** e o vocabulário deve tratá-lo sempre como asserção do remetente, nunca como identidade verificada.

**B-number** — o número de destino discado, extraído da Request-URI. Chega **não canônico**: pode vir como `+E164`, `00…`, `011…`, `9011…`, `0…` ou pelado.

**Peer** — a entidade de interconexão que envia o tráfego, identificada pelo endereço IP de origem. É a única identidade **não forjável** na posição de observação do sistema, e por isso serve de âncora de confiança. Um peer pode ser uma operadora wholesale, um PBX de cliente ou um tronco.

**Unidade de aprendizado** — o par `(peer, A-number)`. É sobre ela que o comportamento é aprendido. Ver [[chave-hierarquica]] na resolução do ticket 09.

**Tenant** — evitar. O termo carrega noção de cliente provisionado que este sistema não tem. Usar **peer** ou **unidade de aprendizado**, conforme o nível.

---

## Destino

**Canonicalização** — converter o B-number discado em E.164. Pré-requisito de qualquer afirmação sobre destino, inclusive comportamental: 20,3% dos destinos do corpus histórico não resolvem a país sem despelamento de prefixo.

**País de destino** — o país do B-number canonicalizado. Alfabeto de ~200 valores. É a granularidade em que a novidade funciona.

**Faixa** — um prefixo de B-number com os últimos N dígitos ignorados. Unidade **durável** da inteligência de destino: persistência medida de 41–68% em 24 meses, contra 0% do número exato.

**IPRN** — *International Premium Rate Number*. O número para o qual a fraude liga e de onde vem a receita partilhada. Pela ITU-T E.169.2 a única faixa premium internacional legítima é `+979`; **todo IRSF observado é numeração nacional comum sequestrada**, e por isso continua parecendo numeração comum.

**Estrutura de destino** — o que se sabe do B-number a partir de plano de numeração público: comprimento válido, faixa alocada, tipo do número. Não é lista de inimigos e não envelhece.

**Reputação de destino** — o que se sabe do B-number a partir de corpus de fraude. Apodrece, e não é fundação deste sistema.

---

## Sinais

**Novidade** — primeira ocorrência de um valor categórico para uma unidade de aprendizado: primeiro país, primeira faixa, primeiro horário. **É o sinal comportamental primário do sistema.** Auto-calibra: a taxa de novidade cai conforme a unidade amadurece.

**Aquecimento** — período inicial em que uma unidade ainda não tem histórico suficiente para que sua novidade signifique algo. Medido em 7 dias para novidade de país.

**Rajada** e **fan-out** — **termos rejeitados**. Registrados aqui para que não voltem por engano. *Rajada* (taxa de chamadas) foi medida como marginal: varia 30× entre casos reais. *Fan-out* (razão de destinos distintos por chamada) foi **refutado**: mediana legítima de 0,60, com três de quatro casos reais de fraude ficando abaixo dela. O fraudador **repete** poucos destinos com chamadas longas, porque a receita é por minuto.

**Cadeia A** — o ataque que arromba: rajada de `401`/`407`, depois `REGISTER` bem-sucedido de IP novo, depois destino internacional inédito.

**Cadeia B** — o ataque que já tem a senha: credencial furtada no servidor de provisionamento por HTTP, depois `REGISTER` bem-sucedido **de primeira**. Não produz falha de autenticação nenhuma e é invisível no plano SIP.

---

## Decisão e ação

**Veredito** — o resultado da avaliação de uma tentativa: **permitir**, **desafiar** ou **negar**.

**Desafio** — desviar a tentativa para verificação (captcha por voz, PIN) em vez de negá-la. Existe para que o caso ambíguo nunca precise de um limiar de apetite a risco.

**Perímetro** — a camada que remove ruído: varredura, força bruta, IP de má reputação, user-agent de ferramenta conhecida. **Não existe para pegar fraude**; existe para impedir que lixo contamine a linha de base comportamental. Ativa desde a instalação.

**Comportamento** — a camada que decide sobre fraude, a partir do que aprendeu de cada unidade. Ativa após o modo de aprendizado.

**Modo de aprendizado** — os primeiros 30 dias, em que a camada de comportamento observa e **não bloqueia**, anunciando isso explicitamente. O perímetro bloqueia normalmente nesse período.

**Silêncio** — não responder a uma tentativa. Aplicado a **endereços de produção** contra atacante, porque qualquer resposta confirma endpoint vivo e convida escalada. **Não** se aplica a cliente legítimo, que recebe resposta, nem a **iscas**, que respondem deliberadamente.

**Isca** — ramal ou DID ocioso usado como armadilha. Tráfego dirigido a uma isca é suspeito por definição.

---

## Caminhos

**Caminho de decisão** — do `INVITE` ao veredito. Sem estado de diálogo, sem consulta externa, sem inferência de modelo pesado. Uma falha aqui é uma falha de proteção.

**Caminho de aprendizado** — assíncrono. Reconstrói diálogos, mede duração e desfecho, atualiza perfis. **Pode perder eventos sem comprometer a proteção**; uma falha aqui degrada o aprendizado, não o bloqueio.
