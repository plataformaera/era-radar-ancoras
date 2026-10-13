# ERA Radar · log público das âncoras do acervo

Este repositório guarda, fora da Plataforma ERA, a âncora de cada carga diária do acervo do ERA Radar (a prova bruta
das fontes oficiais, a memória climática e o estado do dia). O acervo fica no repositório privado da Plataforma ERA;
aqui chegam só as impressões digitais dele. Cada carga diária vira uma âncora: o sha256 de cada arquivo da carga é uma
folha, as folhas formam uma árvore de Merkle, a raiz se encadeia à âncora anterior, e a raiz encadeada vai ao
OpenTimestamps, que a grava no Bitcoin.

Quem tiver um arquivo do acervo confere, sem depender da Plataforma ERA, que ele existia daquele jeito na data da
âncora. Quem reescrever um arquivo depois muda o sha256 dele; o sha256 antigo já está aqui, no histórico do git, e no
Bitcoin.

É o mesmo mecanismo das âncoras do ERA Impacto (github.com/plataformaera/era-impacto-ancoras), num log próprio do Radar.

## Arquivos

- `ancoras/NNNNNN.json`: uma âncora por carga diária, com os carimbos OpenTimestamps.
- `ancoras.jsonl`: uma linha por âncora (número, hora, raiz encadeada, sha256 do arquivo da âncora).
- `scripts/ancora_radar.py`: o cálculo, o carimbo, a confirmação e a conferência, em Python 3.9 só com a biblioteca
  padrão.

## O que pode entrar aqui

Só número da âncora, data, hashes sha256 e carimbos OpenTimestamps. Cada `ancoras/NNNNNN.json` tem apenas estes campos:
`seq`, `quando`, `n_folhas`, `raiz`, `anterior`, `raiz_encadeada`, `folhas` (o sha256 de cada arquivo da carga, em
ordem), `regra` e `provas` (`calendario`, `tipo`, `bloco`, `ots_base64`, `quando`). Nenhum conteúdo de dado e nenhum
nome de arquivo entram neste repositório.

`python3 scripts/ancora_radar.py formato` confere esse formato e o encadeamento antes de cada gravação e em todo pull
request; campo fora da lista, hash fora do padrão ou encadeamento quebrado reprova.

## A regra

```
folha          = sha256(arquivo), em hex
nível 0        = sha256(0x00 || folha)
nó             = sha256(0x01 || esquerda || direita)   (o nível 0 entra ordenado; com número ímpar, o último sobe inteiro)
raiz encadeada = sha256(raiz encadeada anterior em hex || raiz em hex)
```

## Conferir uma âncora

```bash
python3 scripts/ancora_radar.py verificar ancoras/000002.json --anterior ancoras/000001.json --rede
```

Recalcula a raiz a partir das folhas, confere o encadeamento com a anterior, confere que cada carimbo é sobre a raiz
encadeada e, com `--rede`, confere o carimbo confirmado contra a raiz de Merkle do bloco do Bitcoin (blockstream.info).

## Conferir um arquivo do acervo

```bash
python3 scripts/ancora_radar.py folha caminho/do/arquivo.json
```

Calcula o sha256 do arquivo e diz em que âncora ele está. O mesmo à mão: `shasum -a 256 arquivo.json` e procurar o
resultado em `ancoras/`.

## Conferir pelo cliente oficial do OpenTimestamps

```bash
pip install opentimestamps-client
jq -r '.provas[-1].ots_base64' ancoras/000001.json | base64 -d > ancora-000001.ots
ots info ancora-000001.ots
ots verify -d "$(jq -r .raiz_encadeada ancoras/000001.json)" ancora-000001.ots
```

## Como as âncoras chegam aqui

A âncora nasce no fim da carga diária do acervo (`ERA_Radar/scripts/job_acervo_github.py`) e entra direto no `main`,
carimbada nos calendários `a.pool` e `b.pool` do OpenTimestamps. A cada três horas o GitHub Actions
(`.github/workflows/confirmar.yml`) busca a confirmação no Bitcoin dos carimbos pendentes. O `main` não aceita
reescrita nem exclusão. Contato: contato@plataformaera.com.
