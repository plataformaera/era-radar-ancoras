#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ancora_radar.py · âncora pública do acervo do ERA Radar (decisão da Arquiteta de 13/10/2026).

Uma âncora por carga diária do acervo: a árvore de Merkle dos sha256 dos arquivos da carga, encadeada à âncora anterior
e carimbada no OpenTimestamps (Bitcoin), nos mesmos calendários do ERA Impacto. O log público
(github.com/plataformaera/era-radar-ancoras) guarda só número, data, hashes e carimbos; nenhum conteúdo de dado e nenhum
nome de arquivo. O mesmo mecanismo das âncoras do ERA Impacto (era-plataforma, supabase/functions/api/_era/impactoAncora.js),
num log próprio do Radar.

Regra (igual à do ERA Impacto, com a folha = sha256 do arquivo em hex):
  folha = sha256(arquivo) em hex; nivel0 = sha256(0x00 || folha); nó = sha256(0x01 || esquerda || direita);
  o nível 0 entra ordenado; com número ímpar, o último sobe inteiro; raiz encadeada = sha256(anterior_hex || raiz_hex).

Arquivo único, só biblioteca padrão do Python 3.9: o mesmo texto vive em era-sistema (ERA_Radar/scripts/ancora_radar.py,
usado pelo job_acervo_github.py) e em era-radar-ancoras (scripts/ancora_radar.py, usado pelo GitHub Actions e por quem
quiser conferir). Uso pela linha de comando:
  python3 ancora_radar.py verificar ancoras/000001.json [--anterior ancoras/000000.json] [--rede]
  python3 ancora_radar.py folha <arquivo de dado> [--pasta ancoras]   # em que âncora está este arquivo
  python3 ancora_radar.py confirmar [--pasta ancoras]                 # carimba as sem carimbo e busca o Bitcoin
  python3 ancora_radar.py formato [--pasta .]                         # o log só tem número, data, hashes e carimbos
"""
import base64
import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

CALENDARIOS = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org"]
CABECALHOS_OTS = {"Accept": "application/vnd.opentimestamps.v1",
                  "User-Agent": "ERA-Radar/1.0 (contato@plataformaera.com)"}
REGRA = ("folha=sha256(arquivo)_hex; nivel0=sha256(0x00||folha); no=sha256(0x01||esq||dir); impar sobe; "
         "encadeada=sha256(anterior_hex||raiz_hex)")
ESPERA_CONFIRMACAO = 2 * 3600  # o calendário leva algumas horas para levar o compromisso ao Bitcoin

HEX64 = re.compile(r"^[0-9a-f]{64}$")
DATA = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")
CAMPOS = {"seq", "quando", "n_folhas", "raiz", "anterior", "raiz_encadeada", "folhas", "regra", "provas"}
CAMPOS_PROVA = {"calendario", "tipo", "bloco", "ots_base64", "quando"}
CAMPOS_LINHA = {"seq", "quando", "raiz_encadeada", "sha256_do_arquivo"}


# ─── Merkle ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def sha256(b):
    return hashlib.sha256(b).digest()


def sha256_arquivo(caminho):
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(1 << 20), b""):
            h.update(bloco)
    return h.hexdigest()


def nivel0(folha):
    return sha256(b"\x00" + folha.encode("utf-8")).hex()


def raiz_de_merkle(nivel0_hex):
    if not nivel0_hex:
        return None
    nivel = [bytes.fromhex(h) for h in sorted(nivel0_hex)]
    while len(nivel) > 1:
        prox = []
        for i in range(0, len(nivel), 2):
            prox.append(nivel[i] if i == len(nivel) - 1 else sha256(b"\x01" + nivel[i] + nivel[i + 1]))
        nivel = prox
    return nivel[0].hex()


def raiz_encadeada(anterior_hex, raiz_hex):
    return sha256(("%s%s" % (anterior_hex or "", raiz_hex)).encode("utf-8")).hex()


def montar_ancora(seq, folhas, anterior="", quando=None):
    """A âncora de uma carga: folhas = sha256 (hex) dos arquivos. Repetidas contam uma vez."""
    folhas = sorted({f.lower() for f in folhas})
    if not folhas or not all(HEX64.match(f) for f in folhas):
        raise ValueError("as folhas são sha256 em hex, ao menos uma")
    raiz = raiz_de_merkle([nivel0(f) for f in folhas])
    quando = quando or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"seq": int(seq), "quando": quando, "n_folhas": len(folhas), "raiz": raiz, "anterior": anterior or "",
            "raiz_encadeada": raiz_encadeada(anterior, raiz), "folhas": folhas, "regra": REGRA, "provas": []}


def conferir_ancora(ancora, anterior=None):
    """Lista de problemas (vazia = confere): raiz recalculada, encadeamento e número de folhas."""
    problemas = []
    folhas = ancora.get("folhas") or []
    raiz = raiz_de_merkle([nivel0(f) for f in folhas])
    if raiz != ancora.get("raiz"):
        problemas.append("a raiz recalculada (%s) não bate com a publicada (%s)" % (raiz, ancora.get("raiz")))
    if anterior is not None and ancora.get("anterior") != anterior.get("raiz_encadeada"):
        problemas.append("o encadeamento não aponta a âncora anterior")
    if raiz_encadeada(ancora.get("anterior"), ancora.get("raiz")) != ancora.get("raiz_encadeada"):
        problemas.append("a raiz encadeada não bate com anterior + raiz")
    if len(folhas) != ancora.get("n_folhas"):
        problemas.append("o número de folhas não bate")
    return problemas


# ─── OpenTimestamps (formato público, opentimestamps.org) ────────────────────────────────────────────────────────────
# .ots = cabeçalho + versão 1 + operação sha256 + resumo de 32 bytes + carimbo. O carimbo é uma árvore de operações
# (append, prepend, sha256...) que termina em atestações: pendente (um calendário promete) ou bloco do Bitcoin.
CABECALHO_OTS = bytes([0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73,
                       0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94])
TAG_PENDENTE = "83dfe30d2ef90c8e"
TAG_BITCOIN = "0588960d73d71901"
OP_BINARIA = {0xf0: "append", 0xf1: "prepend"}
OP_UNARIA = {0x08: "sha256", 0x02: "sha1", 0x03: "ripemd160", 0x67: "keccak256", 0xf2: "reverse", 0xf3: "hexlify"}


class Leitor(object):
    def __init__(self, b):
        self.b, self.i = b, 0

    def byte(self):
        if self.i >= len(self.b):
            raise ValueError("carimbo truncado")
        self.i += 1
        return self.b[self.i - 1]

    def bytes(self, n):
        if self.i + n > len(self.b):
            raise ValueError("carimbo truncado")
        self.i += n
        return self.b[self.i - n:self.i]

    def varuint(self):
        v, m = 0, 1
        while True:
            x = self.byte()
            v += (x & 0x7f) * m
            m *= 128
            if not x & 0x80:
                return v

    def varbytes(self):
        return self.bytes(self.varuint())

    def fim(self):
        return self.i >= len(self.b)


def _varuint(v):
    out = bytearray()
    while True:
        x = v % 128
        v //= 128
        out.append(x | 0x80 if v else x)
        if not v:
            return bytes(out)


def _varbytes(b):
    return _varuint(len(b)) + b


def _aplicar(op, msg):
    if op["nome"] == "append":
        return msg + op["arg"]
    if op["nome"] == "prepend":
        return op["arg"] + msg
    if op["nome"] == "sha256":
        return sha256(msg)
    if op["nome"] == "reverse":
        return msg[::-1]
    if op["nome"] == "hexlify":
        return msg.hex().encode()
    raise ValueError("operação %s fora do que o verificador aceita" % op["nome"])


def _ler_carimbo(l, msg):
    c = {"msg": msg, "atestacoes": [], "ops": []}

    def item(tag):
        if tag == 0x00:
            t = l.bytes(8).hex()
            carga = l.varbytes()
            lc = Leitor(carga)
            if t == TAG_PENDENTE:
                c["atestacoes"].append({"tipo": "pendente", "uri": lc.varbytes().decode("utf-8"), "tag": t, "carga": carga})
            elif t == TAG_BITCOIN:
                c["atestacoes"].append({"tipo": "bitcoin", "altura": lc.varuint(), "tag": t, "carga": carga})
            else:
                c["atestacoes"].append({"tipo": "outra", "tag": t, "carga": carga})
        elif tag in OP_BINARIA:
            op = {"tag": tag, "nome": OP_BINARIA[tag], "arg": l.varbytes()}
            c["ops"].append((op, _ler_carimbo(l, _aplicar(op, msg))))
        elif tag in OP_UNARIA:
            op = {"tag": tag, "nome": OP_UNARIA[tag]}
            c["ops"].append((op, _ler_carimbo(l, _aplicar(op, msg))))
        else:
            raise ValueError("marca desconhecida no carimbo: 0x%x" % tag)

    while True:
        tag = l.byte()
        if tag == 0xff:
            item(l.byte())
            continue
        item(tag)
        return c


def _escrever_carimbo(c):
    itens = [b"\x00" + bytes.fromhex(a["tag"]) + _varbytes(a["carga"]) for a in c["atestacoes"]]
    itens += [bytes([op["tag"]]) + (_varbytes(op["arg"]) if "arg" in op else b"") + _escrever_carimbo(filho)
              for op, filho in c["ops"]]
    if not itens:
        raise ValueError("carimbo vazio")
    return b"".join(b"\xff" + x for x in itens[:-1]) + itens[-1]


def ler_ots(b):
    l = Leitor(b)
    if l.bytes(len(CABECALHO_OTS)) != CABECALHO_OTS:
        raise ValueError("não é um arquivo .ots")
    if l.varuint() != 1:
        raise ValueError("versão de .ots fora do padrão")
    if l.byte() != 0x08:
        raise ValueError("o .ots da âncora é sobre sha256")
    resumo = l.bytes(32)
    carimbo = _ler_carimbo(l, resumo)
    if not l.fim():
        raise ValueError("sobram bytes depois do carimbo")
    return resumo.hex(), carimbo


def escrever_ots(resumo_hex, carimbo):
    return CABECALHO_OTS + _varuint(1) + b"\x08" + bytes.fromhex(resumo_hex) + _escrever_carimbo(carimbo)


def ots_da_resposta(resumo_hex, resposta):
    """A resposta do calendário ao POST /digest é um carimbo relativo ao resumo enviado."""
    return escrever_ots(resumo_hex, _ler_carimbo(Leitor(resposta), bytes.fromhex(resumo_hex)))


def atestacoes(carimbo):
    out = []

    def anda(c):
        for a in c["atestacoes"]:
            out.append(dict(a, compromisso=c["msg"].hex()))
        for _, filho in c["ops"]:
            anda(filho)
    anda(carimbo)
    return out


def completar(carimbo, compromisso_hex, resposta):
    """Junta ao carimbo o pedaço que o calendário devolve para um compromisso pendente."""
    def anda(c):
        if c["msg"].hex() == compromisso_hex:
            novo = _ler_carimbo(Leitor(resposta), c["msg"])
            c["atestacoes"] = [a for a in c["atestacoes"] if a["tipo"] != "pendente"] + novo["atestacoes"]
            c["ops"] = c["ops"] + novo["ops"]
            return True
        return any(anda(filho) for _, filho in c["ops"])
    return anda(carimbo)


def bate_com_bloco(compromisso_hex, merkle_root_exibido):
    """A raiz de Merkle do bloco vem invertida na exibição dos exploradores; o compromisso usa a ordem interna."""
    return compromisso_hex == bytes.fromhex(merkle_root_exibido)[::-1].hex()


# ─── rede: carimbo e confirmação ─────────────────────────────────────────────────────────────────────────────────────
def _curl(url, corpo, cabecalhos, tempo):
    """O mesmo pedido pelo curl: o Python 3.9 do macOS (LibreSSL 2.8) não fecha o TLS com alguns calendários."""
    fd, saida = tempfile.mkstemp(prefix="ancora_http_")
    os.close(fd)
    try:
        cmd = ["curl", "-sS", "--max-time", str(tempo), "-o", saida, "-w", "%{http_code}"]
        for k, v in cabecalhos.items():
            cmd += ["-H", "%s: %s" % (k, v)]
        if corpo is not None:
            cmd += ["-X", "POST", "--data-binary", "@-"]
        r = subprocess.run(cmd + [url], input=corpo, capture_output=True, timeout=tempo + 10)
        if r.returncode:
            raise RuntimeError("curl: %s" % r.stderr.decode("utf-8", "replace").strip()[:200])
        with open(saida, "rb") as f:
            return int(r.stdout.decode().strip() or 0), f.read()
    finally:
        os.remove(saida)


def _http(url, corpo=None, cabecalhos=None, tempo=20):
    cabecalhos = cabecalhos or CABECALHOS_OTS
    req = urllib.request.Request(url, data=corpo, headers=cabecalhos, method="POST" if corpo else "GET")
    try:
        with urllib.request.urlopen(req, timeout=tempo) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""
    except (urllib.error.URLError, ssl.SSLError) as e:
        if "SSL" not in str(e) or not shutil.which("curl"):
            raise
        return _curl(url, corpo, cabecalhos, tempo)


def _agora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (int(time.time() * 1000) % 1000)


def carimbar(raiz_encadeada_hex, calendarios=None, http=_http):
    """Uma prova pendente por calendário que respondeu; (provas, falhas)."""
    provas, falhas = [], []
    for cal in calendarios or CALENDARIOS:
        try:
            st, corpo = http(cal + "/digest", bytes.fromhex(raiz_encadeada_hex))
            if st != 200:
                raise RuntimeError("HTTP %s" % st)
            ots = ots_da_resposta(raiz_encadeada_hex, corpo)
            provas.append({"calendario": cal, "tipo": "pendente", "bloco": None,
                           "ots_base64": base64.b64encode(ots).decode(), "quando": _agora()})
        except Exception as e:
            falhas.append("%s: %s" % (cal, e))
    return provas, falhas


def confirmar(ancora, http=_http, agora=None):
    """Como o carimbarAncoras do ERA Impacto: âncora sem carimbo vai aos calendários; prova pendente com mais de 2 horas
    busca a confirmação no Bitcoin e, confirmada, entra como prova nova (só acréscimo). Devolve (mudou, falhas)."""
    agora = agora or time.time()
    provas = ancora.setdefault("provas", [])
    if not provas:
        novas, falhas = carimbar(ancora["raiz_encadeada"], http=http)
        provas.extend(novas)
        return bool(novas), falhas
    if any(p["tipo"] == "completa" for p in provas):
        return False, []
    falhas = []
    for p in [x for x in provas if x["tipo"] == "pendente"]:
        quando = datetime.strptime(p["quando"][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        if agora - quando <= ESPERA_CONFIRMACAO:
            continue
        try:
            resumo, carimbo = ler_ots(base64.b64decode(p["ots_base64"]))
            mudou = False
            for at in [a for a in atestacoes(carimbo) if a["tipo"] == "pendente"]:
                st, corpo = http("%s/timestamp/%s" % (at["uri"], at["compromisso"]))
                if st == 404:
                    continue
                if st != 200:
                    raise RuntimeError("HTTP %s" % st)
                mudou = completar(carimbo, at["compromisso"], corpo) or mudou
            btc = [a for a in atestacoes(carimbo) if a["tipo"] == "bitcoin"]
            if mudou and btc:
                provas.append({"calendario": p["calendario"], "tipo": "completa", "bloco": btc[0]["altura"],
                               "ots_base64": base64.b64encode(escrever_ots(resumo, carimbo)).decode(), "quando": _agora()})
                return True, falhas
        except Exception as e:
            falhas.append("confirmação da âncora %s (%s): %s" % (ancora.get("seq"), p["calendario"], e))
    return False, falhas


# ─── o log público ───────────────────────────────────────────────────────────────────────────────────────────────────
def nome_da_ancora(seq):
    return "%06d.json" % int(seq)


def texto_da_ancora(ancora):
    return json.dumps(ancora, ensure_ascii=False, indent=1) + "\n"


def ancoras_do_log(pasta):
    if not os.path.isdir(pasta):
        return []
    return sorted(int(n[:6]) for n in os.listdir(pasta) if re.match(r"^\d{6}\.json$", n))


def ler_ancora(pasta, seq):
    with open(os.path.join(pasta, nome_da_ancora(seq)), encoding="utf-8") as f:
        return json.load(f)


def gravar_no_log(raiz_log, ancora):
    """Grava ancoras/NNNNNN.json e a linha do ancoras.jsonl. Só acréscimo: âncora que já existe não se regrava aqui."""
    pasta = os.path.join(raiz_log, "ancoras")
    os.makedirs(pasta, exist_ok=True)
    caminho = os.path.join(pasta, nome_da_ancora(ancora["seq"]))
    if os.path.exists(caminho):
        raise RuntimeError("a âncora %s já está no log" % ancora["seq"])
    texto = texto_da_ancora(ancora)
    with open(caminho, "w", encoding="utf-8") as f:
        f.write(texto)
    linha = {"seq": ancora["seq"], "quando": ancora["quando"], "raiz_encadeada": ancora["raiz_encadeada"],
             "sha256_do_arquivo": hashlib.sha256(texto.encode("utf-8")).hexdigest()}
    with open(os.path.join(raiz_log, "ancoras.jsonl"), "a", encoding="utf-8") as f:
        f.write(json.dumps(linha) + "\n")
    return caminho


def conferir_formato(raiz_log):
    """O log só tem número, data, hashes e carimbos; campo fora da lista ou hash fora do padrão reprova."""
    problemas = []

    def fora(obj, permitidos, onde):
        problemas.extend("%s: campo fora do formato: %s" % (onde, k) for k in obj if k not in permitidos)

    pasta = os.path.join(raiz_log, "ancoras")
    nomes = sorted(n for n in os.listdir(pasta) if n.endswith(".json")) if os.path.isdir(pasta) else []
    anterior = None
    for nome in nomes:
        onde = "ancoras/" + nome
        if not re.match(r"^\d{6}\.json$", nome):
            problemas.append("%s: nome fora do padrão NNNNNN.json" % onde)
        with open(os.path.join(pasta, nome), encoding="utf-8") as f:
            a = json.load(f)
        fora(a, CAMPOS, onde)
        if not isinstance(a.get("seq"), int) or nome_da_ancora(a.get("seq") or 0) != nome:
            problemas.append("%s: seq não é o número do arquivo" % onde)
        if not DATA.match(str(a.get("quando"))):
            problemas.append("%s: data fora do padrão" % onde)
        for k in ("raiz", "raiz_encadeada"):
            if not HEX64.match(str(a.get(k))):
                problemas.append("%s: %s não é sha256" % (onde, k))
        if a.get("anterior") != "" and not HEX64.match(str(a.get("anterior"))):
            problemas.append("%s: anterior não é sha256" % onde)
        for i, h in enumerate(a.get("folhas") or []):
            if not HEX64.match(str(h)):
                problemas.append("%s: folha %d não é sha256" % (onde, i))
        for i, p in enumerate(a.get("provas") or []):
            fora(p, CAMPOS_PROVA, "%s prova %d" % (onde, i))
            if not re.match(r"^https://[a-z0-9.-]+(/|$)", str(p.get("calendario"))):
                problemas.append("%s prova %d: calendário fora do padrão" % (onde, i))
            if not re.match(r"^[A-Za-z0-9+/=]+$", str(p.get("ots_base64"))):
                problemas.append("%s prova %d: carimbo não é base64" % (onde, i))
        problemas.extend("%s: %s" % (onde, x) for x in conferir_ancora(a, anterior))
        anterior = a
    jl = os.path.join(raiz_log, "ancoras.jsonl")
    if os.path.exists(jl):
        with open(jl, encoding="utf-8") as f:
            for i, l in enumerate(x for x in f.read().split("\n") if x):
                o = json.loads(l)
                fora(o, CAMPOS_LINHA, "ancoras.jsonl linha %d" % (i + 1))
                if not HEX64.match(str(o.get("raiz_encadeada"))) or not HEX64.match(str(o.get("sha256_do_arquivo"))):
                    problemas.append("ancoras.jsonl linha %d: hash fora do padrão" % (i + 1))
    return problemas, len(nomes)


# ─── linha de comando ────────────────────────────────────────────────────────────────────────────────────────────────
def _opc(args, nome, padrao=None):
    return args[args.index(nome) + 1] if nome in args else padrao


def _verificar(args):
    with open(args[0], encoding="utf-8") as f:
        a = json.load(f)
    ant = None
    if "--anterior" in args:
        with open(_opc(args, "--anterior"), encoding="utf-8") as f:
            ant = json.load(f)
    falhou = False
    print("Âncora nº %s · %s · %s folha(s)" % (a.get("seq"), a.get("quando"), a.get("n_folhas")))
    probs = conferir_ancora(a, ant)
    for p in probs:
        print("✗ %s" % p)
    if not probs:
        print("✓ raiz de Merkle e encadeamento conferem%s" % (" (anterior nº %s)" % ant["seq"] if ant else ""))
    falhou = bool(probs)
    for p in a.get("provas") or []:
        try:
            resumo, carimbo = ler_ots(base64.b64decode(p["ots_base64"]))
            if resumo != a["raiz_encadeada"]:
                falhou = True
                print("✗ carimbo de %s: o resumo não é a raiz encadeada" % p["calendario"])
                continue
            ats = atestacoes(carimbo)
            btc = [x for x in ats if x["tipo"] == "bitcoin"]
            if not btc:
                print("✓ carimbo de %s: resumo confere; confirmação no Bitcoin a caminho" % p["calendario"])
            for x in btc:
                if "--rede" not in args:
                    print("✓ carimbo de %s: atestado no bloco %s (use --rede para conferir o bloco)" % (p["calendario"], x["altura"]))
                    continue
                cab = {"User-Agent": CABECALHOS_OTS["User-Agent"]}
                _, h = _http("https://blockstream.info/api/block-height/%s" % x["altura"], cabecalhos=cab)
                _, b = _http("https://blockstream.info/api/block/%s" % h.decode().strip(), cabecalhos=cab)
                bloco = json.loads(b)
                if bate_com_bloco(x["compromisso"], bloco["merkle_root"]):
                    print("✓ carimbo de %s: confere com a raiz de Merkle do bloco %s do Bitcoin (%s)" % (
                        p["calendario"], x["altura"], datetime.fromtimestamp(bloco["timestamp"], timezone.utc).isoformat()))
                else:
                    falhou = True
                    print("✗ carimbo de %s: o compromisso não é a raiz de Merkle do bloco %s" % (p["calendario"], x["altura"]))
        except Exception as e:
            falhou = True
            print("✗ carimbo de %s: %s" % (p.get("calendario"), e))
    if not a.get("provas"):
        print("· esta âncora vai aos calendários OpenTimestamps na próxima confirmação")
    return 1 if falhou else 0


def _folha(args):
    pasta = _opc(args, "--pasta", "ancoras")
    folha = sha256_arquivo(args[0])
    achou = [s for s in ancoras_do_log(pasta) if folha in (ler_ancora(pasta, s).get("folhas") or [])]
    for s in achou:
        print("✓ sha256 %s está na âncora nº %s" % (folha, s))
    if not achou:
        print("✗ sha256 %s não está em nenhuma âncora de %s" % (folha, pasta))
    return 0 if achou else 1


def _confirmar(args):
    pasta = _opc(args, "--pasta", "ancoras")
    mudaram = 0
    for s in ancoras_do_log(pasta)[-60:]:
        a = ler_ancora(pasta, s)
        mudou, falhas = confirmar(a)
        for x in falhas:
            print("aviso: âncora %s: %s" % (s, x))
        if mudou:
            with open(os.path.join(pasta, nome_da_ancora(s)), "w", encoding="utf-8") as f:
                f.write(texto_da_ancora(a))
            mudaram += 1
    print("%d âncora(s) com carimbo novo" % mudaram)
    return 0


def _formato(args):
    probs, n = conferir_formato(_opc(args, "--pasta", "."))
    for p in probs:
        print("✗ %s" % p)
    if not probs:
        print("✓ formato conferido: %d âncora(s), só número, data, hashes e carimbos" % n)
    return 1 if probs else 0


def main(argv):
    cmds = {"verificar": _verificar, "folha": _folha, "confirmar": _confirmar, "formato": _formato}
    if not argv or argv[0] not in cmds:
        print(__doc__)
        return 2
    return cmds[argv[0]](argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
