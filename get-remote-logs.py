#!/usr/bin/env python3
import argparse
import getpass
import ipaddress
import re
import shlex
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Set, Tuple


class Ansi:
    reset = "\033[0m"
    yellow = "\033[33m"
    green = "\033[32m"
    red = "\033[31m"

    @staticmethod
    def maybe_disable(enabled: bool) -> None:
        if not enabled:
            for attr in ("reset", "yellow", "green", "red"):
                setattr(Ansi, attr, "")


def positive_int(value: str) -> int:
    linhas = int(value)
    if linhas <= 0:
        raise argparse.ArgumentTypeError("o número de linhas deve ser um inteiro positivo")
    return linhas


IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def resolve_host_ips(host: str) -> Tuple[Set[str], Set[IpAddress]]:
    """Resolve o host para endereços IP e apelidos comuns."""

    aliases: set[str] = set()
    addr_objects: set[IpAddress] = set()
    errors: list[str] = []

    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            records = socket.getaddrinfo(host, None, family=family)
        except socket.gaierror as exc:
            errors.append(str(exc))
            continue

        for info in records:
            sockaddr = info[4]
            if not sockaddr:
                continue
            ip = sockaddr[0]
            if isinstance(ip, (bytes, bytearray)):
                ip = ip.decode("ascii", "ignore")
            else:
                ip = str(ip)
            expanded = _expand_ip_aliases(ip)
            aliases.update(expanded)
            for candidate in expanded:
                try:
                    addr_objects.add(ipaddress.ip_address(candidate))
                except ValueError:
                    continue

    # Tentativa extra para resolvers que só retornam IPv4
    try:
        host_info = socket.gethostbyname_ex(host)
    except socket.gaierror as exc:
        errors.append(str(exc))
    else:
        for ip in host_info[2]:
            expanded = _expand_ip_aliases(ip)
            aliases.update(expanded)
            for candidate in expanded:
                try:
                    addr_objects.add(ipaddress.ip_address(candidate))
                except ValueError:
                    continue

    if not aliases and errors:
        print(
            f"{Ansi.yellow}Aviso: não foi possível resolver {host}: {', '.join(errors)}{Ansi.reset}",
            file=sys.stderr,
        )
    return aliases, addr_objects


def _expand_ip_aliases(ip: str) -> set[str]:
    aliases = {ip, ip.lower()}
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return aliases

    if isinstance(addr, ipaddress.IPv4Address):
        mapped = f"::ffff:{addr.compressed}"
        aliases.update({addr.compressed, addr.exploded, mapped, mapped.lower()})
    else:
        aliases.update({addr.compressed, addr.compressed.lower(), addr.exploded.lower(), addr.exploded})

    return aliases


def should_ignore_client_ip(
    client_ip: str,
    host_aliases: Set[str],
    host_addr_objects: Set[IpAddress],
) -> bool:
    candidate = client_ip.strip()
    if not candidate:
        return False

    # Remove colchetes opcionais de endereços IPv6 como [2001:db8::1]
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
        if not candidate:
            return False

    candidate_lower = candidate.lower()
    if candidate in host_aliases or candidate_lower in host_aliases:
        return True

    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return False

    if addr.is_loopback:
        return True

    if addr in host_addr_objects:
        return True

    if isinstance(addr, ipaddress.IPv4Address):
        mapped = ipaddress.IPv6Address(f"::ffff:{addr.compressed}")
        if mapped in host_addr_objects:
            return True

    return False


CLIENT_ERROR_REGEX = re.compile(r"\[client\s+(?P<client>[^\]]+)\]")
AUTH_LOG_REGEX = re.compile(r"Connection from\s+(?P<ip>\S+).*?port\s+(?P<port>\d+)", re.IGNORECASE)


def extrair_ip_log(linha: str, tipo_erro: bool, tipo_auth: bool) -> Optional[Tuple[str, Optional[str]]]:
    """Obtém IP e porta relevantes, conforme formatação do log."""

    if tipo_auth:
        match_auth = AUTH_LOG_REGEX.search(linha)
        if not match_auth:
            return None
        ip = match_auth.group("ip").strip().strip("[]")
        porta = match_auth.group("port").strip()
        return ip, porta

    if tipo_erro:
        match = CLIENT_ERROR_REGEX.search(linha)
        if not match:
            return None
        cliente_bruto = match.group("client").strip()
        if not cliente_bruto:
            return None

        candidato = cliente_bruto.split()[0]
        porta: Optional[str] = None

        # Formatos como [IPv6]:porta
        if candidato.startswith("["):
            fechamento = candidato.find("]")
            if fechamento != -1:
                ip_puro = candidato[1:fechamento]
                restante = candidato[fechamento + 1 :]
                if restante.startswith(":") and restante[1:].isdigit():
                    porta = restante[1:]
                candidato = ip_puro
            else:
                candidato = candidato.lstrip("[")

        # Último ':' com dígitos representa porta (IPv4 ou IPv6)
        if ":" in candidato:
            ip_parte, _, porta_parte = candidato.rpartition(":")
            if porta_parte.isdigit() and ip_parte:
                porta = porta_parte
                candidato = ip_parte

        return (candidato, porta)

    # Access log: utilizar primeiro campo, porta opcional para IPv4
    if not linha:
        return None
    primeiro = linha.split(None, 1)[0]
    token = primeiro.strip().strip("[]")
    porta: Optional[str] = None

    if ":" in token:
        ip_parte, _, porta_parte = token.rpartition(":")
        if porta_parte.isdigit() and ip_parte:
            porta = porta_parte
            token = ip_parte

    return (token, porta)


def run_tail(host: str, port: int, username: str, remote_file: str, line_count: int) -> int:
    print(f"{Ansi.yellow}Conectando em {username}@{host}:{port}\u2026{Ansi.reset}", file=sys.stderr)
    host_aliases, host_addr_objects = resolve_host_ips(host)
    ssh_password = getpass.getpass("Senha SSH (deixe em branco para usar chave/agente): ")

    default_answer = "yes"
    sudo_same = input(
        f"A senha do sudo é igual à senha SSH? [{default_answer}/no]: "
    ).strip().lower()

    if sudo_same in ("", "y", "yes") and ssh_password:
        sudo_password = ssh_password
    else:
        sudo_password = getpass.getpass("Senha sudo: ")

    if not sudo_password:
        print(
            f"{Ansi.red}Uma senha sudo é necessária para continuar.{Ansi.reset}",
            file=sys.stderr,
        )
        return 1

    remote_cmd = f"sudo -S -p '' tail -n {line_count} {shlex.quote(remote_file)}"
    ssh_cmd = ["ssh", "-tt", "-p", str(port), f"{username}@{host}", remote_cmd]

    proc = subprocess.Popen(
        ssh_cmd,
        stdin=subprocess.PIPE,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if proc.stdin is None:
        print(f"{Ansi.red}O processo SSH não forneceu stdin.{Ansi.reset}", file=sys.stderr)
        return 1

    # Provide SSH password if supplied (ssh itself consumes it before remote command executes)
    if ssh_password:
        try:
            proc.stdin.write(ssh_password + "\n")
            proc.stdin.flush()
        except BrokenPipeError:
            print(f"{Ansi.red}Falha ao enviar a senha SSH (broken pipe).{Ansi.reset}", file=sys.stderr)
            return 1

    try:
        proc.stdin.write(sudo_password + "\n")
        proc.stdin.flush()
    except BrokenPipeError:
        print(f"{Ansi.red}Falha ao enviar a senha sudo (broken pipe).{Ansi.reset}", file=sys.stderr)
        return 1
    finally:
        proc.stdin.close()

    # Stream stdout with simple color highlighting
    if proc.stdout is None or proc.stderr is None:
        print(f"{Ansi.red}O processo SSH não forneceu streams de saída.{Ansi.reset}", file=sys.stderr)
        return 1

    linhas_emitidas = 0
    linhas_filtradas = 0
    linhas_validas = 0

    eh_error_log = Path(remote_file).name.lower() == "error.log"
    eh_auth_log = Path(remote_file).name.lower() == "auth.log"
    contador_ips: dict[Tuple[str, Optional[str]], int] = {}

    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M")
    output_path = Path(f"{Path(remote_file).name}_{timestamp}.txt")

    try:
        destino = output_path.open("w", encoding="utf-8")
    except OSError as exc:
        print(
            f"{Ansi.red}Não foi possível criar o arquivo de saída {output_path}: {exc}{Ansi.reset}",
            file=sys.stderr,
        )
        destino = None

    for line in proc.stdout:
        if "DigitalOcean" in line or "mod_pagespeed" in line or "munin" in line:
            linhas_filtradas += 1
            continue

        stripped = line.rstrip()
        if not stripped:
            linhas_filtradas += 1
            continue

        ip_info = extrair_ip_log(stripped, eh_error_log, eh_auth_log)
        if ip_info is None:
            linhas_filtradas += 1
            continue

        ip_sem_porta, porta = ip_info

        if should_ignore_client_ip(ip_sem_porta, host_aliases, host_addr_objects):
            linhas_filtradas += 1
            continue

        if eh_error_log and "[client " not in stripped:
            linhas_filtradas += 1
            continue

        if eh_error_log or eh_auth_log:
            chave = (ip_sem_porta, porta)
            contador_ips[chave] = contador_ips.get(chave, 0) + 1
            linhas_validas += 1
            continue

        linha_saida = stripped

        print(f"{Ansi.green}{linha_saida}{Ansi.reset}")
        if destino is not None:
            destino.write(linha_saida + "\n")
        linhas_emitidas += 1
        linhas_validas += 1
    proc.stdout.close()

    if contador_ips:
        for (ip_sem_porta, porta), quantidade in contador_ips.items():
            if porta:
                linha_agregada = f"{ip_sem_porta} {porta} {quantidade}"
            else:
                linha_agregada = f"{ip_sem_porta} {quantidade}"

            print(f"{Ansi.green}{linha_agregada}{Ansi.reset}")
            if destino is not None:
                destino.write(linha_agregada + "\n")

        linhas_emitidas = len(contador_ips)

    if destino is not None:
        destino.close()

    stderr_output = proc.stderr.read()
    proc.stderr.close()
    if stderr_output:
        print(f"{Ansi.red}{stderr_output.rstrip()}{Ansi.reset}", file=sys.stderr)

    if destino is not None:
        print(
            f"{Ansi.yellow}Saída salva em {output_path}.{Ansi.reset}",
            file=sys.stderr,
        )

    linhas_consideradas = linhas_validas
    if linhas_consideradas < line_count:
        faltando = line_count - linhas_consideradas
        print(
            f"{Ansi.yellow}Aviso: {faltando} linhas foram filtradas ou não estavam disponíveis.{Ansi.reset}",
            file=sys.stderr,
        )
    if linhas_filtradas:
        print(
            f"{Ansi.yellow}Linhas ignoradas pelos filtros: {linhas_filtradas}.{Ansi.reset}",
            file=sys.stderr,
        )

    return proc.wait()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Busca as últimas N linhas de um arquivo remoto via ssh e sudo tail.",
    )
    parser.add_argument("host", help="Remote host or IP address")
    parser.add_argument("username", help="SSH username")
    parser.add_argument("remote_file", help="Remote file path to read")
    parser.add_argument(
        "-n",
        "--lines",
        type=positive_int,
        default=50,
        help="Número de linhas a buscar (padrão: 50)",
    )
    parser.add_argument("-p", "--port", type=int, default=None, help="Porta SSH (padrão: 22)")
    args = parser.parse_args()

    port = args.port
    if port is None:
        port_input = input("Porta SSH [22]: ").strip()
        if port_input:
            try:
                port = int(port_input)
            except ValueError:
                print(f"{Ansi.red}Porta inválida '{port_input}'.{Ansi.reset}", file=sys.stderr)
                return 1
        else:
            port = 22

    Ansi.maybe_disable(sys.stdout.isatty())
    return run_tail(args.host, port, args.username, args.remote_file, args.lines)


if __name__ == "__main__":
    raise SystemExit(main())
