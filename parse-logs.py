#!/usr/bin/env python3
"""Analisa logs de acesso do Apache e apresenta um resumo simples."""

import argparse
import collections
import re
import sys
from pathlib import Path
from typing import Iterable, Iterator, Optional

try:
    from geoip2.database import Reader  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - biblioteca opcional
    Reader = None

# Expressão regular para o formato combinado de logs HTTP.
LOG_PATTERN = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+\"(?P<method>\S+)\s+(?P<path>[^\s\"]+)\s+(?P<protocol>[^\s\"]+)\"\s+(?P<status>\d{3})\s+(?P<size>\S+)"
)


def ler_linhas(caminho: Optional[Path]) -> Iterator[str]:
    """Lê o conteúdo linha a linha, suportando stdin quando nenhum caminho é informado."""

    if caminho is None:
        for linha in sys.stdin:
            yield linha.rstrip("\n")
        return

    with caminho.open("r", encoding="utf-8", errors="replace") as manipulador:
        for linha in manipulador:
            yield linha.rstrip("\n")


def _path_or_none(valor: Optional[str]) -> Optional[Path]:
    if valor is None:
        return None
    texto = valor.strip()
    if not texto:
        return None
    return Path(texto)


def analisar_logs(linhas: Iterable[str], origem: Optional[Path]) -> dict:
    """Conta ocorrências de IPs e códigos de status."""

    total = 0
    status_por_codigo = collections.Counter()
    acessos_por_ip = collections.Counter()
    origem_auth = origem is not None and origem.name.startswith("auth.log")

    for linha in linhas:
        total += 1
        correspondencia = LOG_PATTERN.match(linha)
        if correspondencia:
            ip, porta = normalizar_ip(correspondencia.group("ip"))
            status = correspondencia.group("status")
            status_por_codigo[status] += 1
        else:
            extraido = extrair_ip_porta_simples(linha, origem_auth)
            if extraido is None:
                continue
            ip, porta = extraido
            status = None

        acessos_por_ip[(ip, porta)] += 1

    return {
        "total": total,
        "processado": sum(status_por_codigo.values()),
        "status": status_por_codigo,
        "ip": acessos_por_ip,
    }


def gerar_linhas_resumo(resumo: dict, geoip: "GeoIPResolver") -> list[str]:
    """Gera as linhas de resumo prontas para exibição ou gravação."""

    linhas = [f"Total de linhas avaliadas: {resumo['total']}"]
    linhas.append("IP                                    Porta  País                 Cidade                Quantidade")
    for ip_porta, quantidade in resumo["ip"].most_common():
        ip, porta = ip_porta
        pais, cidade = geoip.lookup(ip)
        linhas.append(f"{ip:<39} {porta:<5} {pais:<20} {cidade:<22} : {quantidade}")
    return linhas


def normalizar_ip(ip: str) -> tuple[str, str]:
    """Remove colchetes opcionais e separa IP e porta."""

    valor = ip.strip()
    porta = "-"

    # Formato [ip] ou [ip]:porta
    if valor.startswith("["):
        fechamento = valor.find("]")
        if fechamento != -1:
            ip_limpo = valor[1:fechamento]
            restante = valor[fechamento + 1 :]
            if restante.startswith(":") and restante[1:].isdigit():
                porta = restante[1:]
            return ip_limpo, porta

    # Formato ip:porta (IPv4 ou nomes com uma única ocorrência de ':')
    if ":" in valor:
        ip_parte, _, porta_parte = valor.rpartition(":")
        if porta_parte.isdigit() and ip_parte:
            return ip_parte, porta_parte

    return valor, porta


def extrair_ip_porta_simples(linha: str, origem_auth: bool) -> Optional[tuple[str, str]]:
    """Interpreta linhas simples contendo IP e, opcionalmente, porta."""

    tokens = linha.split()
    if not tokens:
        return None

    candidato = tokens[0]
    porta_token: Optional[str] = None

    if origem_auth and ":" in candidato:
        possivel_ip, _, possivel_porta = candidato.rpartition(":")
        if possivel_porta.isdigit() and possivel_ip:
            porta_token = possivel_porta
            candidato = possivel_ip

    if origem_auth:
        if len(tokens) >= 3 and tokens[1].isdigit():
            porta_token = tokens[1]
        elif len(tokens) >= 3 and tokens[2].isdigit():
            porta_token = tokens[2]
    else:
        if len(tokens) > 1 and tokens[1].isdigit():
            porta_token = tokens[1]

    if porta_token:
        candidato = f"{candidato}:{porta_token}"

    ip, porta = normalizar_ip(candidato)
    return ip, porta


class GeoIPResolver:
    """Resolve país e cidade usando bases GeoLite2."""

    def __init__(self, caminho_cidade: Optional[Path], caminho_pais: Optional[Path]) -> None:
        self._cache: dict[str, tuple[str, str]] = {}
        self._leitor_cidade = self._abrir(caminho_cidade)
        self._leitor_pais = self._abrir(caminho_pais)

        if Reader is None:
            print(
                "Biblioteca geoip2 não encontrada; resultados de GeoIP indisponíveis.",
                file=sys.stderr,
            )

    def _abrir(self, caminho: Optional[Path]):
        if Reader is None or caminho is None:
            return None

        try:
            return Reader(str(caminho))
        except FileNotFoundError:
            print(f"Arquivo GeoIP não encontrado: {caminho}", file=sys.stderr)
        except OSError as exc:
            print(f"Falha ao abrir {caminho}: {exc}", file=sys.stderr)
        return None

    def lookup(self, ip: str) -> tuple[str, str]:
        if ip in self._cache:
            return self._cache[ip]

        pais = "N/D"
        cidade = "N/D"

        if self._leitor_cidade is not None:
            try:
                resposta = self._leitor_cidade.city(ip)
                pais = _nome_local(resposta.country)
                cidade = resposta.city.names.get("pt-BR") or resposta.city.name or cidade
            except Exception:
                pass

        if (pais == "N/D" or pais is None) and self._leitor_pais is not None:
            try:
                resposta = self._leitor_pais.country(ip)
                pais = _nome_local(resposta.country)
            except Exception:
                pass

        resultado = (pais or "N/D", cidade or "N/D")
        self._cache[ip] = resultado
        return resultado

    def close(self) -> None:
        for leitor in (self._leitor_cidade, self._leitor_pais):
            if leitor is not None:
                leitor.close()


def _nome_local(country) -> str:
    if country is None:
        return "N/D"
    return (
        country.names.get("pt-BR")
        or country.names.get("en")
        or country.name
        or country.iso_code
        or "N/D"
    )


def listar_arquivos_txt(diretorio: Path) -> list[Path]:
    """Retorna a lista de arquivos .txt do diretório atual."""

    return sorted(
        caminho
        for caminho in diretorio.glob("*.txt")
        if "summary" not in caminho.name
    )


def selecionar_arquivo(arquivos: list[Path]) -> Optional[Path]:
    """Solicita ao usuário que escolha um arquivo entre os listados."""

    if not arquivos:
        print("Nenhum arquivo .txt encontrado no diretório atual.")
        return None

    print("Arquivos .txt disponíveis:")
    for indice, caminho in enumerate(arquivos, start=1):
        print(f"  [{indice}] {caminho.name}")

    escolha = input("Informe o número do arquivo a processar (ENTER para cancelar): ").strip()
    if not escolha:
        print("Nenhum arquivo selecionado.")
        return None

    try:
        indice = int(escolha)
    except ValueError:
        print("Entrada inválida. Utilize apenas números da lista.")
        return None

    if indice < 1 or indice > len(arquivos):
        print("Número fora da faixa apresentada.")
        return None

    return arquivos[indice - 1]


def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analisa arquivos de log do Apache gerados localmente.",
    )
    parser.add_argument(
        "arquivo",
        nargs="?",
        default=None,
        help="Arquivo de log a processar (padrão: perguntar interativamente).",
    )
    parser.add_argument(
        "--geoip-city",
        default="GeoLite2-City.mmdb",
        help="Caminho para o banco GeoLite2-City (padrão: GeoLite2-City.mmdb).",
    )
    parser.add_argument(
        "--geoip-country",
        default="GeoLite2-Country.mmdb",
        help="Caminho para o banco GeoLite2-Country (padrão: GeoLite2-Country.mmdb).",
    )
    return parser


def main() -> int:
    parser = construir_parser()
    argumentos = parser.parse_args()

    caminho = Path(argumentos.arquivo) if argumentos.arquivo else None
    if caminho is None:
        arquivos_txt = listar_arquivos_txt(Path.cwd())
        caminho = selecionar_arquivo(arquivos_txt)
        if caminho is None:
            return 1

    resolver = GeoIPResolver(_path_or_none(argumentos.geoip_city), _path_or_none(argumentos.geoip_country))
    try:
        resumo = analisar_logs(ler_linhas(caminho), caminho)
        linhas = gerar_linhas_resumo(resumo, resolver)

        for linha in linhas:
            print(linha)

        arquivo_saida = caminho.with_name(f"{caminho.name}_summary.txt")
        with arquivo_saida.open("w", encoding="utf-8") as destino:
            destino.write("\n".join(linhas) + "\n")

        print(f"Resumo salvo em {arquivo_saida}.")
    finally:
        resolver.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
