#!/usr/bin/env python3
import argparse
import csv
import json
import socket
import struct
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from html import escape
from ipaddress import ip_network
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set, Tuple


class Ansi:
    reset = "\033[0m"
    green = "\033[32m"
    red = "\033[31m"
    yellow = "\033[33m"

    @staticmethod
    def desativar() -> None:
        for attr in ("reset", "green", "red", "yellow"):
            setattr(Ansi, attr, "")


@dataclass
class CipherEntry:
    name: str
    direction: str
    score: int
    color: str
    label: str
    reason: str
    reference: Optional[str] = None


@dataclass
class AlgorithmEntry:
    name: str
    score: int
    color: str
    label: str
    reason: str
    reference: Optional[str] = None


@dataclass
class ScanResult:
    host: str
    port: int
    banner: str
    version: str
    supports_ssh2: bool
    kex_algorithms: List[AlgorithmEntry]
    host_key_algorithms: List[AlgorithmEntry]
    ciphers: List[CipherEntry]
    macs_client_to_server: List[str]
    macs_server_to_client: List[str]
    first_kex_packet_follows: bool


STRONG_CIPHERS = {
    "chacha20-poly1305@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-ctr@openssh.com",
    "aes256-ctr@openssh.com",
}

WEAK_CIPHERS = {
    "3des-cbc",
    "blowfish-cbc",
    "twofish-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "cast128-cbc",
    "des-cbc",
    "des-ede3-cbc",
    "rijndael-cbc@lysator.liu.se",
    "none",
}

MAX_HOSTS_FROM_RANGE = 4096


NIST_REFERENCES = {
    # Key exchange primitives
    "diffie-hellman-group14-sha256": "https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final",
    "diffie-hellman-group16-sha512": "https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final",
    "diffie-hellman-group18-sha512": "https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final",
    "diffie-hellman-group-exchange-sha256": "https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final",
    "ecdh-sha2-nistp256": "https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final",
    "ecdh-sha2-nistp384": "https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final",
    "ecdh-sha2-nistp521": "https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final",
    "diffie-hellman-group14-sha1": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    "diffie-hellman-group-exchange-sha1": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    "diffie-hellman-group1-sha1": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    # Host key algorithms
    "rsa-sha2-256": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "rsa-sha2-256-cert-v01@openssh.com": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "rsa-sha2-512": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "rsa-sha2-512-cert-v01@openssh.com": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "ecdsa-sha2-nistp256": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "ecdsa-sha2-nistp384": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "ecdsa-sha2-nistp521": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com": "https://csrc.nist.gov/publications/detail/fips/186/5/final",
    "ssh-rsa": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    "ssh-rsa-cert-v01@openssh.com": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    "ssh-dss": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    "ssh-dss-cert-v01@openssh.com": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    # Symmetric ciphers
    "aes128-gcm@openssh.com": "https://csrc.nist.gov/publications/detail/sp/800-38d/final",
    "aes256-gcm@openssh.com": "https://csrc.nist.gov/publications/detail/sp/800-38d/final",
    "aes128-ctr": "https://csrc.nist.gov/publications/detail/sp/800-38a/final",
    "aes192-ctr": "https://csrc.nist.gov/publications/detail/sp/800-38a/final",
    "aes256-ctr": "https://csrc.nist.gov/publications/detail/sp/800-38a/final",
    "aes128-ctr@openssh.com": "https://csrc.nist.gov/publications/detail/sp/800-38a/final",
    "aes256-ctr@openssh.com": "https://csrc.nist.gov/publications/detail/sp/800-38a/final",
    "aes128-cbc": "https://csrc.nist.gov/publications/detail/sp/800-38a/final",
    "aes192-cbc": "https://csrc.nist.gov/publications/detail/sp/800-38a/final",
    "aes256-cbc": "https://csrc.nist.gov/publications/detail/sp/800-38a/final",
    "3des-cbc": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    "des-ede3-cbc": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
    "des-cbc": "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
}


def lookup_nist_reference(name: str) -> Optional[str]:
    """Return the NIST reference URL for the given algorithm name, if known."""

    return NIST_REFERENCES.get(name.lower())


CIPHER_REASONS = {
    "chacha20-poly1305@openssh.com": "2013/2014 AEAD design with 256-bit key and Poly1305 authenticator; resists known attacks as of 2025.",
    "aes128-gcm@openssh.com": "AES-128 (2001) in GCM mode (2007) offering authenticated encryption with 128-bit security.",
    "aes256-gcm@openssh.com": "AES-256 (2001) in GCM mode (2007) providing AEAD and 256-bit security margin.",
    "aes128-ctr": "AES-128 (2001) in CTR mode; 128-bit key remains strong when paired with modern MACs.",
    "aes192-ctr": "AES-192 (2001) in CTR mode; extended key length offers strong margin.",
    "aes256-ctr": "AES-256 (2001) in CTR mode; 256-bit key gives long-term strength.",
    "aes128-ctr@openssh.com": "OpenSSH variant of AES-128 CTR (2001); still secure with 128-bit key.",
    "aes256-ctr@openssh.com": "OpenSSH variant of AES-256 CTR (2001); 256-bit key for high assurance.",
    "3des-cbc": "Triple DES (late 1990s) with 112-bit effective security and 64-bit block; vulnerable to SWEET32 and slow.",
    "blowfish-cbc": "Blowfish (1993) with 64-bit block size; susceptible to SWEET32-style attacks.",
    "twofish-cbc": "Twofish (1998) but used in CBC without authentication; better options exist today.",
    "arcfour": "RC4 (1987) with severe keystream biases discovered in 2000s; deprecated since 2013.",
    "arcfour128": "RC4 variant (1987) limited to 128 bits but still biased; prohibited by modern guidance.",
    "arcfour256": "RC4 variant (1987) with longer key but same statistical weaknesses; deprecated.",
    "aes128-cbc": "AES-128 (2001) in CBC mode; prone to padding-oracle attacks without extra mitigations.",
    "aes192-cbc": "AES-192 (2001) in CBC mode; same padding-oracle issues reduce safety.",
    "aes256-cbc": "AES-256 (2001) in CBC mode; padding oracles and lack of integrity make it risky.",
    "cast128-cbc": "CAST-128 (1996) with 64-bit block; outdated and affected by SWEET32 risks.",
    "des-cbc": "Single DES (1977) with 56-bit key; brute-force feasible since late 1990s.",
    "des-ede3-cbc": "Triple DES (late 1990s) with 112-bit security but 64-bit blocks and slow performance.",
    "rijndael-cbc@lysator.liu.se": "Rijndael precursor to AES (1998) in CBC mode; lacks AEAD protections.",
    "none": "No encryption layer; exposes plaintext over the network.",
}

DEFAULT_STRONG_REASON = "Post-2010 design with >=128-bit keys and authenticated or counter mode; no practical attacks reported by 2025."
DEFAULT_INTERMEDIATE_REASON = "Early-2000s era construction without built-in authentication; acceptable today but upgrade to AEAD soon."
DEFAULT_WEAK_REASON = "Older (pre-2005) design with limited block size or known attacks (e.g., padding or keystream biases)."

STRONG_KEX = {
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "sntrup761x25519-sha512@openssh.com",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group-exchange-sha256",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
}

INTERMEDIATE_KEX = {
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
}

WEAK_KEX = {
    "diffie-hellman-group1-sha1",
}

KEX_REASONS = {
    "curve25519-sha256": "Curve25519 (2014) + SHA-256; ~128-bit strength matching NIST SP 800-57 Level 1 guidance.",
    "curve25519-sha256@libssh.org": "Libssh.org Curve25519 (2014) w/ SHA-256; aligns with NIST >=128-bit recommendations.",
    "sntrup761x25519-sha512@openssh.com": "Hybrid NTRU Prime 761 + X25519 (2020) with SHA-512, exceeding NIST Level 1 minimums.",
    "diffie-hellman-group14-sha256": "2048-bit MODP Group14 + SHA-256 (2014 refresh) satisfies NIST 112-bit baseline.",
    "diffie-hellman-group16-sha512": "4096-bit MODP Group16 + SHA-512 exceeds NIST Level 1 (112-bit) recommendations.",
    "diffie-hellman-group18-sha512": "8192-bit MODP Group18 + SHA-512 provides Level 2+ margin per NIST SP 800-57.",
    "diffie-hellman-group-exchange-sha256": "RFC 4419 (2006) DH with negotiated >=2048-bit primes and SHA-256; meets NIST baseline.",
    "ecdh-sha2-nistp256": "ECDH on NIST P-256 (2009) ~128-bit strength as required by NIST for Level 1.",
    "ecdh-sha2-nistp384": "ECDH on NIST P-384 (2009) ~192-bit, aligning with NIST Level 2 guidance.",
    "ecdh-sha2-nistp521": "ECDH on NIST P-521 (2009) ~256-bit, meeting NIST Level 3 goals.",
    "diffie-hellman-group14-sha1": "2048-bit Group14 (2002) but SHA-1 hashing; marginal vs NIST guidance due to hash aging.",
    "diffie-hellman-group-exchange-sha1": "Negotiated DH with SHA-1 (2006); migrate to SHA-256 for NIST compliance.",
    "diffie-hellman-group1-sha1": "1024-bit Group1 + SHA-1 (1997); below NIST 112-bit minimum and considered broken.",
}

DEFAULT_STRONG_KEX_REASON = "Meets or exceeds NIST SP 800-57 Level 1 (>=112-bit) using SHA-2 family primitives."
DEFAULT_INTERMEDIATE_KEX_REASON = "At or near NIST minimums but held back by SHA-1 reliance; upgrade recommended."
DEFAULT_WEAK_KEX_REASON = "Falls below NIST 112-bit baseline or uses SHA-1 exclusively; treat as deprecated."

STRONG_HOST_KEYS = {
    "ssh-ed25519",
    "ssh-ed25519-cert-v01@openssh.com",
    "sk-ssh-ed25519@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "rsa-sha2-256",
    "rsa-sha2-256-cert-v01@openssh.com",
    "rsa-sha2-512",
    "rsa-sha2-512-cert-v01@openssh.com",
}

WEAK_HOST_KEYS = {
    "ssh-rsa",
    "ssh-rsa-cert-v01@openssh.com",
    "ssh-dss",
    "ssh-dss-cert-v01@openssh.com",
}

HOST_KEY_REASONS = {
    "ssh-ed25519": "Ed25519 (2014) ~128-bit strength with SHA-512; exceeds NIST Level 1 recommendations.",
    "ssh-ed25519-cert-v01@openssh.com": "Certificate Ed25519 (2014) + SHA-512; NIST-compliant modern default.",
    "sk-ssh-ed25519@openssh.com": "FIDO2 Ed25519 (2019) hardware-backed, satisfying NIST >=128-bit guidance.",
    "sk-ssh-ed25519-cert-v01@openssh.com": "FIDO2 Ed25519 cert (2019) + SHA-512; strong per NIST Level 1.",
    "sk-ecdsa-sha2-nistp256@openssh.com": "FIDO2 ECDSA P-256 (2019) with SHA-256; meets NIST Level 1.",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com": "FIDO2 ECDSA P-256 cert (2019); NIST Level 1 compliant.",
    "ecdsa-sha2-nistp256": "ECDSA P-256 (2009) ~128-bit strength per NIST Level 1.",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com": "ECDSA P-256 cert (2009); meets NIST Level 1.",
    "ecdsa-sha2-nistp384": "ECDSA P-384 (2009) ~192-bit security, exceeding NIST Level 2 baseline.",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com": "ECDSA P-384 cert (2009) ~192-bit; NIST Level 2 ready.",
    "ecdsa-sha2-nistp521": "ECDSA P-521 (2009) ~256-bit, aligned with NIST Level 3.",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com": "ECDSA P-521 cert (2009) ~256-bit; NIST Level 3.",
    "rsa-sha2-256": "RSA with SHA-256 (2018); requires >=2048-bit keys to satisfy NIST Level 1.",
    "rsa-sha2-256-cert-v01@openssh.com": "Certificate RSA + SHA-256 (2018); compliant for >=2048-bit keys.",
    "rsa-sha2-512": "RSA with SHA-512 (2018); strong hash and >=2048-bit RSA meets NIST Level 1.",
    "rsa-sha2-512-cert-v01@openssh.com": "Certificate RSA + SHA-512 (2018); strong per NIST Level 1.",
    "ssh-rsa": "RSA with SHA-1 (2006); fails NIST guidance due to SHA-1 collisions.",
    "ssh-rsa-cert-v01@openssh.com": "Certificate RSA SHA-1 (2006); non-compliant with NIST mandates.",
    "ssh-dss": "DSA limited to 1024-bit modulus (1994); below NIST minimum 112-bit strength.",
    "ssh-dss-cert-v01@openssh.com": "DSA 1024-bit cert (1994); deprecated under NIST guidance.",
}

DEFAULT_STRONG_HOST_REASON = "Meets NIST SP 800-57 Level 1 (>=2048-bit RSA or >=128-bit ECC) with SHA-2/Ed25519."
DEFAULT_INTERMEDIATE_HOST_REASON = "Near NIST baseline but missing SHA-2 or hardware assurances; migrate soon."
DEFAULT_WEAK_HOST_REASON = "Below NIST minimum strength or uses SHA-1; treat as deprecated."


def parse_host_port(value: str, default_port: int) -> Tuple[str, int]:
    token = value.strip()
    if not token:
        return "", default_port

    if token.startswith("["):
        end_bracket = token.find("]")
        if end_bracket == -1:
            raise ValueError(f"Invalid host format '{value}' (missing closing bracket).")
        host = token[1:end_bracket]
        remainder = token[end_bracket + 1 :]
        if remainder.startswith(":"):
            port_part = remainder[1:]
            if not port_part:
                raise ValueError(f"Missing port after host in '{value}'.")
            try:
                port = int(port_part)
            except ValueError as exc:
                raise ValueError(f"Invalid port '{port_part}' in '{value}'.") from exc
            if port <= 0 or port > 65535:
                raise ValueError(f"Port out of range in '{value}'.")
            return host, port
        if remainder:
            raise ValueError(f"Invalid host format '{value}'.")
        return host, default_port

    if ":" in token:
        host_part, port_part = token.rsplit(":", 1)
        if port_part.isdigit():
            port = int(port_part)
            if port <= 0 or port > 65535:
                raise ValueError(f"Port out of range in '{value}'.")
            return host_part, port

    return token, default_port


def expandir_entrada(entrada: str, default_port: int) -> List[Tuple[str, int]]:
    alvo_bruto = entrada.split("#", 1)[0].strip()
    if not alvo_bruto:
        return []

    host_token, port = parse_host_port(alvo_bruto, default_port)

    try:
        rede = ip_network(host_token, strict=False)
    except ValueError:
        return [(host_token, port)]

    if rede.num_addresses > MAX_HOSTS_FROM_RANGE:
        raise ValueError(
            f"Network {host_token} expands to {rede.num_addresses} addresses; limit is {MAX_HOSTS_FROM_RANGE}."
        )

    if rede.num_addresses <= 1:
        return [(str(rede.network_address), port)]

    hosts = [str(host) for host in rede.hosts()]
    hosts = hosts or [str(rede.network_address)]
    return [(host, port) for host in hosts]


def recolher_alvos(args: argparse.Namespace, default_port: int) -> List[Tuple[str, int]]:
    entradas: List[str] = []
    if args.alvo:
        entradas.append(args.alvo)
    if args.range:
        entradas.append(args.range)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as handler:
                for linha in handler:
                    entradas.append(linha.strip())
        except OSError as exc:
            raise ValueError(f"Could not read {args.file}: {exc}") from exc

    vistos: Set[Tuple[str, int]] = set()
    resultado: List[Tuple[str, int]] = []
    for item in entradas:
        for alvo in expandir_entrada(item, default_port):
            if alvo[0] and alvo not in vistos:
                resultado.append(alvo)
                vistos.add(alvo)
    return resultado


def receber_banner(sock: socket.socket, timeout: float) -> str:
    sock.settimeout(timeout)
    dados = bytearray()
    while not dados.endswith(b"\n"):
        bloco = sock.recv(1)
        if not bloco:
            break
        dados.extend(bloco)
        if len(dados) > 1024:
            raise RuntimeError("SSH banner exceeded 1 KiB without a newline.")
    return dados.decode("ascii", errors="replace").strip()


def enviar_banner(sock: socket.socket) -> None:
    sock.sendall(b"SSH-2.0-SSHScanner\r\n")


def receber_pacote(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    cabecalho = _receber_exato(sock, 4)
    comprimento = struct.unpack(">I", cabecalho)[0]
    if comprimento > 35000:
        raise RuntimeError(f"Unexpectedly large packet ({comprimento} bytes).")
    comprimento_padding = _receber_exato(sock, 1)[0]
    payload_len = comprimento - comprimento_padding - 1
    payload = _receber_exato(sock, payload_len)
    _receber_exato(sock, comprimento_padding)  # discard padding bytes
    return payload


def _receber_exato(sock: socket.socket, nbytes: int) -> bytes:
    dados = bytearray()
    while len(dados) < nbytes:
        parte = sock.recv(nbytes - len(dados))
        if not parte:
            raise RuntimeError("Connection closed prematurely.")
        dados.extend(parte)
    return bytes(dados)


def ler_name_list(buffer: bytes, offset: int) -> Tuple[List[str], int]:
    tamanho = struct.unpack(">I", buffer[offset:offset + 4])[0]
    offset += 4
    lista = buffer[offset:offset + tamanho].decode("ascii", errors="replace")
    offset += tamanho
    return (lista.split(",")) if lista else [], offset


def interpretar_kexinit(payload: bytes) -> dict:
    if not payload or payload[0] != 20:  # SSH_MSG_KEXINIT
        raise RuntimeError("First packet is not SSH_MSG_KEXINIT.")
    idx = 1 + 16  # skip message type and cookie
    campos = {}
    campos["kex_algorithms"], idx = ler_name_list(payload, idx)
    campos["server_host_key_algorithms"], idx = ler_name_list(payload, idx)
    campos["encryption_algorithms_client_to_server"], idx = ler_name_list(payload, idx)
    campos["encryption_algorithms_server_to_client"], idx = ler_name_list(payload, idx)
    campos["mac_algorithms_client_to_server"], idx = ler_name_list(payload, idx)
    campos["mac_algorithms_server_to_client"], idx = ler_name_list(payload, idx)
    campos["compression_algorithms_client_to_server"], idx = ler_name_list(payload, idx)
    campos["compression_algorithms_server_to_client"], idx = ler_name_list(payload, idx)
    campos["languages_client_to_server"], idx = ler_name_list(payload, idx)
    campos["languages_server_to_client"], idx = ler_name_list(payload, idx)
    campos["first_kex_packet_follows"] = bool(payload[idx])
    return campos


def classificar_versao(banner: str) -> str:
    if banner.startswith("SSH-1."):
        return "SSH v1"
    if banner.startswith("SSH-1.99"):
        return "SSH v2 (server also accepts v1)"
    if banner.startswith("SSH-2.") or banner.startswith("SSH-2"):
        return "SSH v2"
    return "Version not recognized"


def classificar_cifra(nome: str) -> Tuple[int, str, str, str]:
    nome_lower = nome.lower()

    if nome_lower in STRONG_CIPHERS or nome_lower.endswith("-gcm@openssh.com"):
        reason = CIPHER_REASONS.get(nome_lower, DEFAULT_STRONG_REASON)
        return 0, Ansi.green, "strong", reason

    if (
        nome_lower in WEAK_CIPHERS
        or nome_lower.endswith("-cbc")
        or nome_lower.startswith("arcfour")
        or nome_lower.startswith("3des")
    ):
        reason = CIPHER_REASONS.get(nome_lower, DEFAULT_WEAK_REASON)
        return 2, Ansi.red, "weak", reason

    if nome_lower.endswith("-ctr") and nome_lower.startswith("aes"):
        reason = CIPHER_REASONS.get(nome_lower, DEFAULT_STRONG_REASON)
        return 0, Ansi.green, "strong", reason

    reason = CIPHER_REASONS.get(nome_lower, DEFAULT_INTERMEDIATE_REASON)
    return 1, Ansi.yellow, "intermediate", reason


def cipher_sort_key(nome: str) -> Tuple[int, int, str]:
    score, _, _, _ = classificar_cifra(nome)
    tie = 0
    nome_lower = nome.lower()

    if score == 0:
        if "poly1305" in nome_lower:
            tie = 0
        elif "gcm" in nome_lower:
            tie = 1
        elif nome_lower.endswith("-ctr"):
            tie = 2
        else:
            tie = 3
    elif score == 1:
        if nome_lower.endswith("-ctr"):
            tie = 1
        else:
            tie = 2
    else:
        tie = 0

    return score, tie, nome_lower


def classificar_kex(nome: str) -> Tuple[int, str, str, str]:
    nome_lower = nome.lower()

    if nome_lower in STRONG_KEX:
        reason = KEX_REASONS.get(nome_lower, DEFAULT_STRONG_KEX_REASON)
        return 0, Ansi.green, "strong", reason

    if nome_lower in INTERMEDIATE_KEX:
        reason = KEX_REASONS.get(nome_lower, DEFAULT_INTERMEDIATE_KEX_REASON)
        return 1, Ansi.yellow, "intermediate", reason

    if nome_lower in WEAK_KEX:
        reason = KEX_REASONS.get(nome_lower, DEFAULT_WEAK_KEX_REASON)
        return 2, Ansi.red, "weak", reason

    if any(token in nome_lower for token in ("curve25519", "sntrup", "sha256", "sha512", "nistp")):
        reason = KEX_REASONS.get(nome_lower, DEFAULT_STRONG_KEX_REASON)
        return 0, Ansi.green, "strong", reason

    if nome_lower.endswith("sha1"):
        reason = KEX_REASONS.get(nome_lower, DEFAULT_WEAK_KEX_REASON)
        return 2, Ansi.red, "weak", reason

    reason = KEX_REASONS.get(nome_lower, DEFAULT_INTERMEDIATE_KEX_REASON)
    return 1, Ansi.yellow, "intermediate", reason


def classificar_host_key(nome: str) -> Tuple[int, str, str, str]:
    nome_lower = nome.lower()

    if nome_lower in STRONG_HOST_KEYS:
        reason = HOST_KEY_REASONS.get(nome_lower, DEFAULT_STRONG_HOST_REASON)
        return 0, Ansi.green, "strong", reason

    if nome_lower in WEAK_HOST_KEYS:
        reason = HOST_KEY_REASONS.get(nome_lower, DEFAULT_WEAK_HOST_REASON)
        return 2, Ansi.red, "weak", reason

    if (
        nome_lower.startswith("ssh-ed25519")
        or nome_lower.startswith("sk-")
        or nome_lower.endswith("-sha512")
        or nome_lower.endswith("-sha256")
    ):
        reason = HOST_KEY_REASONS.get(nome_lower, DEFAULT_STRONG_HOST_REASON)
        return 0, Ansi.green, "strong", reason

    if nome_lower.endswith("-sha1") or nome_lower.endswith("dss") or nome_lower == "ssh-rsa":
        reason = HOST_KEY_REASONS.get(nome_lower, DEFAULT_WEAK_HOST_REASON)
        return 2, Ansi.red, "weak", reason

    reason = HOST_KEY_REASONS.get(nome_lower, DEFAULT_INTERMEDIATE_HOST_REASON)
    return 1, Ansi.yellow, "intermediate", reason


def scan_target(host: str, port: int, timeout: float) -> ScanResult:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        banner = receber_banner(sock, timeout)
        version = classificar_versao(banner)
        supports_ssh2 = banner.startswith(("SSH-2.", "SSH-1.99"))

        if not supports_ssh2:
            return ScanResult(
                host=host,
                port=port,
                banner=banner,
                version=version,
                supports_ssh2=False,
                kex_algorithms=[],
                host_key_algorithms=[],
                ciphers=[],
                macs_client_to_server=[],
                macs_server_to_client=[],
                first_kex_packet_follows=False,
            )

        enviar_banner(sock)
        try:
            payload = receber_pacote(sock, timeout)
        except RuntimeError as exc:
            raise RuntimeError(f"Failed to read SSH_MSG_KEXINIT: {exc}") from exc

        campos = interpretar_kexinit(payload)

        kex_entries: List[AlgorithmEntry] = []
        for alg in campos["kex_algorithms"]:
            score, color, label, reason = classificar_kex(alg)
            reference = lookup_nist_reference(alg)
            kex_entries.append(
                AlgorithmEntry(alg, score, color, label, reason, reference)
            )
        kex_entries.sort(key=lambda entry: entry.score)

        host_entries: List[AlgorithmEntry] = []
        for alg in campos["server_host_key_algorithms"]:
            score, color, label, reason = classificar_host_key(alg)
            reference = lookup_nist_reference(alg)
            host_entries.append(
                AlgorithmEntry(alg, score, color, label, reason, reference)
            )
        host_entries.sort(key=lambda entry: entry.score)

        ciphers: List[CipherEntry] = []
        ciphers_cts = sorted(
            campos["encryption_algorithms_client_to_server"],
            key=cipher_sort_key,
        )
        for cipher in ciphers_cts:
            score, color, label, reason = classificar_cifra(cipher)
            reference = lookup_nist_reference(cipher)
            ciphers.append(
                CipherEntry(
                    cipher,
                    "client->server",
                    score,
                    color,
                    label,
                    reason,
                    reference,
                )
            )

        ciphers_stc = sorted(
            campos["encryption_algorithms_server_to_client"],
            key=cipher_sort_key,
        )
        for cipher in ciphers_stc:
            score, color, label, reason = classificar_cifra(cipher)
            reference = lookup_nist_reference(cipher)
            ciphers.append(
                CipherEntry(
                    cipher,
                    "server->client",
                    score,
                    color,
                    label,
                    reason,
                    reference,
                )
            )

        return ScanResult(
            host=host,
            port=port,
            banner=banner,
            version=version,
            supports_ssh2=True,
            kex_algorithms=kex_entries,
            host_key_algorithms=host_entries,
            ciphers=ciphers,
            macs_client_to_server=campos["mac_algorithms_client_to_server"],
            macs_server_to_client=campos["mac_algorithms_server_to_client"],
            first_kex_packet_follows=campos["first_kex_packet_follows"],
        )


def format_scan_result(result: ScanResult, use_color: bool) -> str:
    lines: List[str] = []
    lines.append(f"Remote banner: {result.banner}")
    lines.append(f"Version classification: {result.version}")

    if not result.supports_ssh2:
        lines.append("Server does not advertise SSH v2 support; stopping analysis.")
        return "\n".join(lines)

    lines.append("\nKey exchange algorithms (kex_algorithms):")
    for entry in result.kex_algorithms:
        color = entry.color if use_color else ""
        reset = Ansi.reset if use_color else ""
        name = f"{color}{entry.name}{reset}" if color else entry.name
        reference = f" [NIST: {entry.reference}]" if entry.reference else ""
        lines.append(f"  - {name} ({entry.label} - {entry.reason}{reference})")

    lines.append("\nHost key algorithms (server_host_key_algorithms):")
    for entry in result.host_key_algorithms:
        color = entry.color if use_color else ""
        reset = Ansi.reset if use_color else ""
        name = f"{color}{entry.name}{reset}" if color else entry.name
        reference = f" [NIST: {entry.reference}]" if entry.reference else ""
        lines.append(f"  - {name} ({entry.label} - {entry.reason}{reference})")

    for direction, heading in (
        ("client->server", "Offered ciphers (client->server):"),
        ("server->client", "Offered ciphers (server->client):"),
    ):
        lines.append(f"\n{heading}")
        for entry in (c for c in result.ciphers if c.direction == direction):
            color = entry.color if use_color else ""
            reset = Ansi.reset if use_color else ""
            name = f"{color}{entry.name}{reset}" if color else entry.name
            reference = f" [NIST: {entry.reference}]" if entry.reference else ""
            lines.append(f"  - {name} ({entry.label} - {entry.reason}{reference})")

    lines.append("\nProposed MACs (client->server):")
    for mac in result.macs_client_to_server:
        lines.append(f"  - {mac}")

    lines.append("\nProposed MACs (server->client):")
    for mac in result.macs_server_to_client:
        lines.append(f"  - {mac}")

    lines.append(f"\nfirst_kex_packet_follows: {result.first_kex_packet_follows}")
    return "\n".join(lines)


def sanitize_filename(host: str, port: int) -> str:
    safe_host = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in host)
    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    return f"{safe_host}_{port}_{timestamp}"


def compute_strength_stats(result: ScanResult) -> Tuple[int, int, int, int]:
    strong = intermediate = weak = 0

    def consume(entries):
        nonlocal strong, intermediate, weak
        for entry in entries:
            if entry.label == "strong":
                strong += 1
            elif entry.label == "weak":
                weak += 1
            else:
                intermediate += 1

    consume(result.kex_algorithms)
    consume(result.host_key_algorithms)
    consume(result.ciphers)

    score = strong * 2 + intermediate - weak * 2
    if not result.supports_ssh2:
        score -= 5

    return score, strong, intermediate, weak


def result_to_plain_dict(result: ScanResult) -> dict:
    return {
        "host": result.host,
        "port": result.port,
        "banner": result.banner,
        "version": result.version,
        "supports_ssh2": result.supports_ssh2,
        "first_kex_packet_follows": result.first_kex_packet_follows,
        "kex_algorithms": [
            {
                "name": entry.name,
                "strength": entry.label,
                "reason": entry.reason,
                "reference": entry.reference,
            }
            for entry in result.kex_algorithms
        ],
        "host_key_algorithms": [
            {
                "name": entry.name,
                "strength": entry.label,
                "reason": entry.reason,
                "reference": entry.reference,
            }
            for entry in result.host_key_algorithms
        ],
        "ciphers": [
            {
                "name": entry.name,
                "direction": entry.direction,
                "strength": entry.label,
                "reason": entry.reason,
                "reference": entry.reference,
            }
            for entry in result.ciphers
        ],
        "mac_algorithms": {
            "client_to_server": result.macs_client_to_server,
            "server_to_client": result.macs_server_to_client,
        },
    }


def write_text_result(result: ScanResult, path: Path) -> None:
    content = format_scan_result(result, use_color=False)
    path.write_text(content + "\n", encoding="utf-8")


def write_csv_result(result: ScanResult, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "host",
            "port",
            "section",
            "direction",
            "name",
            "strength",
            "reason",
            "reference",
        ])
        writer.writerow([result.host, result.port, "banner", "", result.banner, "", "", ""])
        writer.writerow([result.host, result.port, "version", "", result.version, "", "", ""])
        writer.writerow(
            [
                result.host,
                result.port,
                "first_kex_packet_follows",
                "",
                str(result.first_kex_packet_follows),
                "",
                "",
                "",
            ]
        )

        for entry in result.kex_algorithms:
            writer.writerow(
                [
                    result.host,
                    result.port,
                    "kex_algorithm",
                    "",
                    entry.name,
                    entry.label,
                    entry.reason,
                    entry.reference or "",
                ]
            )

        for entry in result.host_key_algorithms:
            writer.writerow(
                [
                    result.host,
                    result.port,
                    "host_key_algorithm",
                    "",
                    entry.name,
                    entry.label,
                    entry.reason,
                    entry.reference or "",
                ]
            )

        for entry in result.ciphers:
            writer.writerow(
                [
                    result.host,
                    result.port,
                    "cipher",
                    entry.direction,
                    entry.name,
                    entry.label,
                    entry.reason,
                    entry.reference or "",
                ]
            )

        for mac in result.macs_client_to_server:
            writer.writerow([result.host, result.port, "mac", "client->server", mac, "", "", ""])

        for mac in result.macs_server_to_client:
            writer.writerow([result.host, result.port, "mac", "server->client", mac, "", "", ""])


def write_json_result(result: ScanResult, path: Path) -> None:
    payload = result_to_plain_dict(result)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_html_result(result: ScanResult, path: Path) -> None:
    payload = result_to_plain_dict(result)

    def color_for_label(label: str) -> str:
        return {
            "strong": "#2e7d32",
            "intermediate": "#f9a825",
            "weak": "#c62828",
        }.get(label, "#1976d2")

    lines: List[str] = []
    lines.append("<!DOCTYPE html>")
    lines.append("<html><head><meta charset=\"utf-8\"><title>SSH Scan Result</title>")
    lines.append(
        "<style>body{font-family:Menlo,Consolas,monospace;background:#0b0b0b;color:#e0e0e0;padding:16px;}"
        "h1{color:#64b5f6;} table{border-collapse:collapse;margin-top:12px;width:100%;}"
        "th,td{border:1px solid #444;padding:6px;text-align:left;}"
        "th{background:#1c1c1c;} .label{font-weight:bold;}</style>"
    )
    lines.append("</head><body>")
    lines.append(
        f"<h1>SSH Scan Result for {escape(result.host)}:{result.port}</h1>"
    )
    lines.append("<p class=\"label\">Banner:</p><pre>" + escape(result.banner) + "</pre>")
    lines.append(
        "<p class=\"label\">Version classification:</p><pre>"
        + escape(result.version)
        + "</pre>"
    )

    def build_table(title: str, rows: List[dict], include_direction: bool = False) -> None:
        lines.append(f"<h2>{escape(title)}</h2>")
        lines.append("<table><tr>")
        if include_direction:
            lines.append("<th>Direction</th>")
        lines.append("<th>Name</th><th>Strength</th><th>Reason</th><th>Reference</th></tr>")
        for row in rows:
            color = color_for_label(row["strength"])
            cell_parts: List[str] = []
            if include_direction:
                cell_parts.append(f"<td>{escape(row['direction'])}</td>")
            cell_parts.append(f"<td>{escape(row['name'])}</td>")
            cell_parts.append(f"<td style=\"color:{color}\">{escape(row['strength'])}</td>")
            cell_parts.append(f"<td>{escape(row['reason'])}</td>")
            reference = row.get("reference")
            if reference:
                ref_url = escape(reference, quote=True)
                cell_parts.append(f"<td><a href=\"{ref_url}\" target=\"_blank\">NIST</a></td>")
            else:
                cell_parts.append("<td></td>")
            lines.append("<tr>" + "".join(cell_parts) + "</tr>")
        lines.append("</table>")

    build_table("Key Exchange Algorithms", payload["kex_algorithms"])
    build_table("Host Key Algorithms", payload["host_key_algorithms"])
    build_table("Cipher Algorithms", payload["ciphers"], include_direction=True)

    lines.append("<h2>MAC Algorithms</h2>")
    lines.append("<h3>Client to Server</h3><pre>" + escape("\n".join(result.macs_client_to_server)) + "</pre>")
    lines.append("<h3>Server to Client</h3><pre>" + escape("\n".join(result.macs_server_to_client)) + "</pre>")
    lines.append(
        "<p>first_kex_packet_follows: "
        + escape(str(result.first_kex_packet_follows))
        + "</p>"
    )
    lines.append("</body></html>")

    path.write_text("\n".join(lines), encoding="utf-8")


def write_ranking_html(results: List[ScanResult], path: Path) -> None:
    ranking = []
    for res in results:
        score, strong, intermediate, weak = compute_strength_stats(res)
        ranking.append(
            {
                "host": res.host,
                "port": res.port,
                "score": score,
                "strong": strong,
                "intermediate": intermediate,
                "weak": weak,
                "supports_ssh2": res.supports_ssh2,
                "banner": res.banner,
                "version": res.version,
            }
        )

    ranking.sort(key=lambda item: (item["score"], item["strong"], -item["weak"]), reverse=True)

    lines: List[str] = []
    lines.append("<!DOCTYPE html>")
    lines.append("<html><head><meta charset=\"utf-8\"><title>SSH Scan Ranking</title>")
    lines.append(
        "<style>body{font-family:Menlo,Consolas,monospace;background:#111;color:#eaeaea;padding:18px;}"
        "h1{color:#90caf9;} table{border-collapse:collapse;width:100%;margin-top:16px;}"
        "th,td{border:1px solid #444;padding:6px;text-align:left;}"
        "th{background:#1f1f1f;} .weak{color:#ef5350;} .strong{color:#66bb6a;} .intermediate{color:#ffca28;}</style>"
    )
    lines.append("</head><body>")
    lines.append("<h1>Parallel SSH Scan Ranking</h1>")
    lines.append("<table><tr><th>Rank</th><th>Host</th><th>Score</th><th>Strong</th><th>Intermediate</th><th>Weak</th><th>SSH v2</th><th>Banner</th></tr>")

    for idx, entry in enumerate(ranking, start=1):
        supports = "yes" if entry["supports_ssh2"] else "no"
        score_class = "strong" if entry["score"] > 0 else ("weak" if entry["score"] < 0 else "intermediate")
        lines.append("<tr>")
        lines.append(f"<td>{idx}</td>")
        lines.append(
            f"<td>{escape(entry['host'])}:{entry['port']}</td>"
        )
        lines.append(
            f"<td class=\"{score_class}\">{entry['score']}</td><td>{entry['strong']}</td>"
            f"<td>{entry['intermediate']}</td><td class=\"weak\">{entry['weak']}</td><td>{supports}</td>"
        )
        lines.append(f"<td>{escape(entry['banner'])}</td>")
        lines.append("</tr>")

    lines.append("</table>")
    lines.append("</body></html>")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simple SSH banner scanner that lists algorithms/ciphers from KEXINIT."
    )
    parser.add_argument(
        "alvo",
        nargs="?",
        help="Host/IP or CIDR to probe. Append :port or use [IPv6]:port for per-target overrides.",
    )
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH port (default: 22).")
    parser.add_argument(
        "-t", "--timeout", type=float, default=5.0, help="Connection/IO timeout in seconds (default: 5.0)."
    )
    parser.add_argument(
        "-r",
        "--range",
        help="Additional CIDR range to scan (optionally with :port), e.g. 192.168.0.0/28:2222.",
    )
    parser.add_argument(
        "-f",
        "--file",
        help=".conf file listing hosts or CIDR ranges (optionally :port or [IPv6]:port), one per line.",
    )
    parser.add_argument(
        "--parallel-workers",
        type=int,
        default=1,
        help="Number of worker threads. Values >1 enable parallel execution with per-target output files.",
    )
    parser.add_argument(
        "--parallel-output-format",
        choices=("text", "csv"),
        default="text",
        help="Deprecated; parallel mode now writes text, JSON, HTML, and CSV for each target.",
    )
    parser.add_argument(
        "--parallel-output-dir",
        default="ssh_scan_results",
        help="Directory to store per-target outputs when parallel execution is enabled.",
    )

    args = parser.parse_args()

    if args.port <= 0 or args.port > 65535:
        print("--port must be between 1 and 65535.")
        sys.exit(1)

    use_color = sys.stdout.isatty()
    if not use_color:
        Ansi.desativar()
    try:
        alvos = recolher_alvos(args, args.port)
    except ValueError as exc:
        print(exc)
        sys.exit(1)

    if not alvos:
        print("No targets provided.")
        sys.exit(1)

    if args.parallel_workers < 1:
        print("--parallel-workers must be >= 1.")
        sys.exit(1)

    if args.parallel_workers == 1:
        output_dir = Path(args.parallel_output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        collected_results: List[ScanResult] = []

        for host, port in alvos:
            print(f"\n===== {host}:{port} =====")
            try:
                resultado = scan_target(host, port, args.timeout)
            except (socket.error, RuntimeError) as exc:
                print(f"Failed to probe {host}:{port} -> {exc}")
                continue

            collected_results.append(resultado)
            print(format_scan_result(resultado, use_color=use_color))

            base_name = sanitize_filename(host, port)
            text_path = output_dir / f"{base_name}.txt"
            json_path = output_dir / f"{base_name}.json"
            html_path = output_dir / f"{base_name}.html"
            csv_path = output_dir / f"{base_name}.csv"

            write_text_result(resultado, text_path)
            write_json_result(resultado, json_path)
            write_html_result(resultado, html_path)
            write_csv_result(resultado, csv_path)

            print(
                "Saved results for {host}:{port} -> {txt}, {js}, {ht}, {csv}".format(
                    host=host,
                    port=port,
                    txt=text_path.name,
                    js=json_path.name,
                    ht=html_path.name,
                    csv=csv_path.name,
                )
            )

        if collected_results:
            suffix = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
            ranking_path = output_dir / f"summary_ranking_{suffix}.html"
            write_ranking_html(collected_results, ranking_path)
            print(f"Wrote ranking summary to {ranking_path.name}")
    else:
        output_dir = Path(args.parallel_output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        print(
            f"Parallel execution enabled with {args.parallel_workers} workers; writing outputs to {output_dir.resolve()}"
        )

        def task(target_host: str, target_port: int) -> ScanResult:
            return scan_target(target_host, target_port, args.timeout)

        collected_results: List[ScanResult] = []

        with ThreadPoolExecutor(max_workers=args.parallel_workers) as executor:
            futures = {
                executor.submit(task, host, port): (host, port)
                for host, port in alvos
            }

            for future in as_completed(futures):
                host, port = futures[future]
                try:
                    resultado = future.result()
                except (socket.error, RuntimeError) as exc:
                    print(f"Failed to probe {host}:{port} -> {exc}")
                    continue

                collected_results.append(resultado)
                base_name = sanitize_filename(host, port)
                text_path = output_dir / f"{base_name}.txt"
                json_path = output_dir / f"{base_name}.json"
                html_path = output_dir / f"{base_name}.html"
                csv_path = output_dir / f"{base_name}.csv"

                write_text_result(resultado, text_path)
                write_json_result(resultado, json_path)
                write_html_result(resultado, html_path)
                write_csv_result(resultado, csv_path)

                print(
                    "Saved results for {host}:{port} -> {txt}, {js}, {ht}, {csv}".format(
                        host=host,
                        port=port,
                        txt=text_path.name,
                        js=json_path.name,
                        ht=html_path.name,
                        csv=csv_path.name,
                    )
                )

        if collected_results:
            suffix = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
            ranking_path = output_dir / f"summary_ranking_{suffix}.html"
            write_ranking_html(collected_results, ranking_path)
            print(f"Wrote ranking summary to {ranking_path.name}")


if __name__ == "__main__":
    main()