# -*- coding: utf-8 -*-
"""Âncora pública do acervo do ERA Radar (decisão da Arquiteta de 13/10/2026): o cálculo da raiz, a verificação de uma
folha, o carimbo OpenTimestamps e o formato do log. O mesmo arquivo roda em era-sistema (ERA_Radar/tests) e em
era-radar-ancoras (tests), ao lado de scripts/ancora_radar.py."""
import base64
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import ancora_radar as A  # noqa: E402

H = lambda b: hashlib.sha256(b).digest()  # noqa: E731


def _folhas(*textos):
    return [hashlib.sha256(t.encode()).hexdigest() for t in textos]


# ─── raiz ────────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_raiz_de_uma_duas_e_tres_folhas_pela_regra():
    f = sorted(A.nivel0(x) for x in _folhas("a", "b", "c"))
    assert A.nivel0(_folhas("a")[0]) == H(b"\x00" + _folhas("a")[0].encode()).hex()
    assert A.raiz_de_merkle(f[:1]) == f[0]
    assert A.raiz_de_merkle(f[:2]) == H(b"\x01" + bytes.fromhex(f[0]) + bytes.fromhex(f[1])).hex()
    # com número ímpar, o último sobe inteiro
    esq = H(b"\x01" + bytes.fromhex(f[0]) + bytes.fromhex(f[1]))
    assert A.raiz_de_merkle(f) == H(b"\x01" + esq + bytes.fromhex(f[2])).hex()
    # a ordem de entrada não muda a raiz
    assert A.raiz_de_merkle(list(reversed(f))) == A.raiz_de_merkle(f)
    assert A.raiz_de_merkle([]) is None


def test_mesma_conta_das_ancoras_do_era_impacto():
    # âncora nº 2 do log público era-impacto-ancoras (12/10/2026): nível 0, raiz e raiz encadeada publicados
    n0 = ["4010d05bb301fc302590e7f0af5dfabd4656d94db1ffd01290c79b9484ba87a1",
          "58e6d76356b45497c1857de3fd61b811e2f699468e56d2d1fe40ad810bf9ddca",
          "c4c177a9dd97e2c7324eba1a0344895b7b8000dc356a2ac0fa623636dd6dd233"]
    raiz = A.raiz_de_merkle(n0)
    assert raiz == "38d5399f49d33e0c768265fb8cd45283ee14236027221608cc5e2ee55c2e4717"
    assert A.raiz_encadeada("d759b8f0bca0dcaa102e88e957673fcc80a39acb22c297bc5aeaedcda487ed1e", raiz) == \
        "52e64134893766152395db9f39493dcd1cac3e9727341842fa6de9e25e928dcc"


def test_montar_e_conferir_a_ancora():
    a1 = A.montar_ancora(1, _folhas("x", "y", "x"), quando="2026-10-13T23:40:00Z")
    assert a1["n_folhas"] == 2 and a1["anterior"] == "" and a1["folhas"] == sorted(_folhas("x", "y"))
    assert A.conferir_ancora(a1) == []
    a2 = A.montar_ancora(2, _folhas("z"), a1["raiz_encadeada"], quando="2026-10-14T23:40:00Z")
    assert A.conferir_ancora(a2, a1) == []
    assert a2["raiz_encadeada"] == A.raiz_encadeada(a1["raiz_encadeada"], a2["raiz"])
    adulterada = dict(a2, folhas=_folhas("w"))
    assert any("raiz recalculada" in p for p in A.conferir_ancora(adulterada, a1))
    assert any("encadeamento" in p for p in A.conferir_ancora(a2, dict(a1, raiz_encadeada="0" * 64)))


def test_folha_que_nao_e_sha256_nao_entra():
    for ruim in ([], ["nome/do/arquivo.json"], ["ab" * 31]):
        try:
            A.montar_ancora(1, ruim)
            assert False, ruim
        except ValueError:
            pass


# ─── verificação de uma folha ────────────────────────────────────────────────────────────────────────────────────────
def test_verificar_uma_folha_pelo_arquivo(tmp_path, capsys):
    dado = tmp_path / "inmet_20261013.json"
    dado.write_bytes(b'{"estacao": "A201", "chuva_mm": 12.4}')
    outro = tmp_path / "outro.json"
    outro.write_bytes(b"{}")
    pasta = tmp_path / "log" / "ancoras"
    pasta.mkdir(parents=True)
    a = A.montar_ancora(1, [A.sha256_arquivo(str(dado)), _folhas("q")[0]])
    (pasta / "000001.json").write_text(A.texto_da_ancora(a))
    assert A.main(["folha", str(dado), "--pasta", str(pasta)]) == 0
    assert "âncora nº 1" in capsys.readouterr().out
    assert A.main(["folha", str(outro), "--pasta", str(pasta)]) == 1
    # o log guarda o hash do conteúdo, nunca o nome do arquivo
    assert "inmet" not in (pasta / "000001.json").read_text()


# ─── OpenTimestamps ──────────────────────────────────────────────────────────────────────────────────────────────────
def _pendente(uri):
    return b"\x00" + bytes.fromhex(A.TAG_PENDENTE) + A._varbytes(A._varbytes(uri.encode()))


def _bitcoin(altura):
    return b"\x00" + bytes.fromhex(A.TAG_BITCOIN) + A._varbytes(A._varuint(altura))


def _resposta_digest(uri):
    # o que o calendário devolve ao POST /digest: append de um nonce, sha256 e a promessa pendente
    return b"\xf0" + A._varbytes(b"\x11" * 16) + b"\x08" + _pendente(uri)


def _calendario_falso(altura=None):
    def http(url, corpo=None, cabecalhos=None, tempo=20):
        if url.endswith("/digest"):
            return 200, _resposta_digest(url[:-len("/digest")])
        if "/timestamp/" in url:
            return (200, b"\x08" + _bitcoin(altura)) if altura else (404, b"")
        return 500, b""
    return http


def test_ots_ida_e_volta_e_resumo_na_raiz_encadeada():
    resumo = A.montar_ancora(1, _folhas("a"))["raiz_encadeada"]
    ots = A.ots_da_resposta(resumo, _resposta_digest("https://a.pool.opentimestamps.org"))
    r, carimbo = A.ler_ots(ots)
    assert r == resumo
    assert A.escrever_ots(r, carimbo) == ots
    ats = A.atestacoes(carimbo)
    assert [a["tipo"] for a in ats] == ["pendente"]
    assert ats[0]["compromisso"] == H(bytes.fromhex(resumo) + b"\x11" * 16).hex()


def test_carimbo_nos_dois_calendarios_e_confirmacao_no_bitcoin():
    a = A.montar_ancora(1, _folhas("a", "b"))
    mudou, falhas = A.confirmar(a, http=_calendario_falso())
    assert mudou and not falhas
    assert [p["calendario"] for p in a["provas"]] == A.CALENDARIOS
    assert all(p["tipo"] == "pendente" and p["bloco"] is None for p in a["provas"])
    # antes de 2 horas não busca a confirmação; sem bloco ainda, nada muda
    assert A.confirmar(a, http=_calendario_falso(971500)) == (False, [])
    depois = A.time.time() + 3 * 3600
    assert A.confirmar(a, http=_calendario_falso(), agora=depois) == (False, [])
    mudou, _ = A.confirmar(a, http=_calendario_falso(971500), agora=depois)
    assert mudou
    completa = [p for p in a["provas"] if p["tipo"] == "completa"]
    assert len(completa) == 1 and completa[0]["bloco"] == 971500
    r, carimbo = A.ler_ots(base64.b64decode(completa[0]["ots_base64"]))
    assert r == a["raiz_encadeada"]
    assert [x["altura"] for x in A.atestacoes(carimbo) if x["tipo"] == "bitcoin"] == [971500]
    # confirmada, não busca mais
    assert A.confirmar(a, http=_calendario_falso(971501), agora=depois) == (False, [])


def test_bloco_do_bitcoin_na_ordem_interna():
    assert A.bate_com_bloco("0102", "0201")
    assert not A.bate_com_bloco("0102", "0102")


# ─── formato do log ──────────────────────────────────────────────────────────────────────────────────────────────────
def test_formato_do_log(tmp_path):
    log = str(tmp_path)
    a1 = A.montar_ancora(1, _folhas("a"))
    a1["provas"] = A.carimbar(a1["raiz_encadeada"], http=_calendario_falso())[0]
    A.gravar_no_log(log, a1)
    a2 = A.montar_ancora(2, _folhas("b"), a1["raiz_encadeada"])
    A.gravar_no_log(log, a2)
    assert A.conferir_formato(log) == ([], 2)
    linhas = [json.loads(x) for x in open(os.path.join(log, "ancoras.jsonl"))]
    assert [x["seq"] for x in linhas] == [1, 2] and set(linhas[0]) == A.CAMPOS_LINHA
    try:
        A.gravar_no_log(log, a2)
        assert False
    except RuntimeError:
        pass
    # campo fora da lista (um nome de arquivo, por exemplo) reprova
    with open(os.path.join(log, "ancoras", "000002.json"), "w") as f:
        f.write(A.texto_da_ancora(dict(a2, arquivos=["dados/insumos_brutos/x.json"])))
    probs, _ = A.conferir_formato(log)
    assert any("campo fora do formato: arquivos" in p for p in probs)
    # encadeamento quebrado reprova
    with open(os.path.join(log, "ancoras", "000002.json"), "w") as f:
        f.write(A.texto_da_ancora(A.montar_ancora(2, _folhas("b"), "f" * 64)))
    probs, _ = A.conferir_formato(log)
    assert any("encadeamento" in p for p in probs)
