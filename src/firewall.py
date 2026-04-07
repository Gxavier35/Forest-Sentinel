import subprocess
import logging
import platform
import shutil
from abc import ABC, abstractmethod
import ipaddress

from utils import is_admin


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


class BaseFirewall(ABC):
    """Interface abstrata para garantir portabilidade entre diferentes sistemas de Firewall."""

    @abstractmethod
    def block(self, ip: str) -> bool:
        """Bloqueia um endereço IP no Firewall do SO."""
        pass

    @abstractmethod
    def unblock(self, ip: str) -> bool:
        """Remove o bloqueio de um endereço IP no Firewall do SO."""
        pass

    @abstractmethod
    def unblock_all(self):
        """Limpa todas as regras de bloqueio criadas por esta aplicação."""
        pass


class WindowsFirewall(BaseFirewall):
    """Implementaçao para Windows Defender Firewall usando netsh."""

    def __init__(self):
        self.logger = logging.getLogger("Firewall.Windows")
        self._tracked_ips = set()

    def block(self, ip: str) -> bool:
        if not is_valid_ip(ip):
            self.logger.critical(f"Tentativa de Command Injection prevenida. IP Invalido: {ip}")
            return False

        if ip in self._tracked_ips:
            return True

        ip = str(ipaddress.ip_address(ip))
        rule_name = f"DDoS_Block_{ip}"
        
        try:
            # Tentamos adicionar a regra diretamente (mais rápido que show + add)
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=block",
                f"remoteip={ip}", "enable=yes", "profile=any",
                "interfacetype=any", "description=ForestSentinel Active Block",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            
            if res.returncode == 0:
                self.logger.warning(f"🛡️ Bloqueio EFETIVADO via netsh: {ip}")
                self._tracked_ips.add(ip)
                return True
            else:
                out = res.stdout.lower()
                # Se a regra já existir, apenas consideramos sucesso e rastreamos
                if "already exists" in out or "já existe" in out:
                    self._tracked_ips.add(ip)
                    return True
                
                if "access is denied" in out or "acesso negado" in out:
                    self.logger.error(f"Permissão negada ao bloquear {ip}. Execute como Administrador.")
                else:
                    self.logger.error(f"Erro netsh ao bloquear {ip}: {res.stdout.strip()}")
                return False
        except Exception as e:
            self.logger.error(f"Exceção severa ao bloquear fluxo IP {ip}: {e}")
        return False

    def unblock(self, ip: str) -> bool:
        if not is_valid_ip(ip):
            return False

        ip = str(ipaddress.ip_address(ip))
        rule_name = f"DDoS_Block_{ip}"
        try:
            res = subprocess.run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    f"name={rule_name}",
                ],
                capture_output=True,
                text=True,
            )
            if res.returncode == 0 or "No rules match" in res.stdout:
                self.logger.info(f"🔓 IP desbloqueado via netsh: {ip}")
                self._tracked_ips.discard(ip)
                return True
            else:
                self.logger.error(
                    f"Erro imprevisto do netsh no desbloqueio de {ip}: {res.stdout.strip()}"
                )
                return False
        except Exception as e:
            self.logger.error(f"Exceção severa ao desbloquear IP {ip}: {e}")
            return False

    def unblock_all(self):
        for ip in list(self._tracked_ips):
            self.unblock(ip)
        self.logger.warning("🏁 Limpeza sistemática de firewall (Windows) concluída.")


class LinuxFirewall(BaseFirewall):
    """Implementaçao avançada para Linux com suporte a iptables/nftables."""

    def __init__(self):
        self.logger = logging.getLogger("Firewall.Linux")
        self._tracked_ips = set()
        self.has_nft = shutil.which("nft") is not None
        self.has_ipt = shutil.which("iptables") is not None
        self._nft_setup_done = False  # Estado agora é intrínseco à instância

        if self.has_nft and is_admin() and not self._nft_setup_done:
            self._setup_nft()

    def _setup_nft(self):
        try:
            check = subprocess.run(
                ["nft", "list", "table", "ip", "ddos_monitor"],
                capture_output=True,
                text=True,
            )
            if check.returncode != 0:
                subprocess.run(
                    ["nft", "add", "table", "ip", "ddos_monitor"],
                    capture_output=True,
                    check=True,
                )
                subprocess.run(
                    [
                        "nft",
                        "add",
                        "chain",
                        "ip",
                        "ddos_monitor",
                        "input",
                        "{ type filter hook input priority 0 ; }",
                    ],
                    capture_output=True,
                    check=True,
                )
                subprocess.run(
                    [
                        "nft",
                        "add",
                        "set",
                        "ip",
                        "ddos_monitor",
                        "blackhole",
                        "{ type ipv4_addr ; }",
                    ],
                    capture_output=True,
                    check=True,
                )
                subprocess.run(
                    [
                        "nft",
                        "add",
                        "rule",
                        "ip",
                        "ddos_monitor",
                        "input",
                        "ip",
                        "saddr",
                        "@blackhole",
                        "drop",
                    ],
                    capture_output=True,
                    check=True,
                )
                self.logger.info(
                    "NFTables: Estrutura 'ddos_monitor' inicializada com sucesso."
                )
            else:
                self.logger.info("NFTables: Estrutura 'ddos_monitor' já existente.")
            self._nft_setup_done = True
        except Exception as e:
            self.logger.error(f"Falha ao configurar estrutura NFTables: {e}")

    def block(self, ip: str) -> bool:
        if not is_valid_ip(ip):
            self.logger.critical(
                f"Tentativa de Command Injection prevenida. IP Invalido: {ip}"
            )
            return False

        ip = str(ipaddress.ip_address(ip))

        if not is_admin():
            self.logger.error(
                f"❌ Erro de permissão: Execute como root/sudo para bloquear {ip}"
            )
            return False
        success = False
        if self.has_nft:
            success = self._block_nft(ip)
        
        # Fallback para iptables caso nftables falhe ou não esteja disponível
        if not success and self.has_ipt:
            success = self._block_ipt(ip)
            
        return success

    def _block_nft(self, ip: str) -> bool:
        try:
            cmd = [
                "nft",
                "add",
                "element",
                "ip",
                "ddos_monitor",
                "blackhole",
                f"{{ {ip} }}",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                self.logger.warning(f"🛡️ IP bloqueado via nftables (set): {ip}")
                self._tracked_ips.add(ip)
                return True
            return False
        except Exception as e:
            self.logger.error(f"Falha nftables: {e}")
            return False

    def _block_ipt(self, ip: str) -> bool:
        try:
            res_chk = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True
            )
            if res_chk.returncode != 0:
                res = subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True,
                    text=True,
                )
                if res.returncode == 0:
                    self.logger.warning(f"🛡️ IP bloqueado via iptables: {ip}")
                    self._tracked_ips.add(ip)
                    return True
                return False
            self._tracked_ips.add(ip)
            return True
        except Exception as e:
            self.logger.error(f"Falha iptables: {e}")
            return False

    def unblock(self, ip: str) -> bool:
        if not is_valid_ip(ip):
            return False

        ip = str(ipaddress.ip_address(ip))

        if not is_admin():
            self.logger.error(
                f"❌ Erro de permissão: Execute como root/sudo para desbloquear {ip}"
            )
            return False
        self._tracked_ips.discard(ip)
        if self.has_nft:
            res = subprocess.run(
                [
                    "nft",
                    "delete",
                    "element",
                    "ip",
                    "ddos_monitor",
                    "blackhole",
                    f"{{ {ip} }}",
                ],
                capture_output=True,
            )
            if res.returncode == 0:
                self.logger.info(f"🔓 IP desbloqueado via nftables: {ip}")
                return True
            self.logger.error(f"Erro nftables no desbloqueio de {ip}")
            return False
        if self.has_ipt:
            res = subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                text=True,
            )
            if res.returncode == 0:
                self.logger.info(f"🔓 IP desbloqueado via iptables: {ip}")
                return True
            self.logger.error(f"Erro iptables no desbloqueio de {ip}")
            return False
        return False

    def unblock_all(self):
        if not is_admin():
            self.logger.error(
                "❌ Erro de permissão: Execute como root/sudo para limpar bloqueios do firewall"
            )
            return
        if self.has_nft:
            try:
                subprocess.run(
                    ["nft", "flush", "set", "ip", "ddos_monitor", "blackhole"],
                    capture_output=True,
                    check=True,
                )
                self.logger.info("NFTables: Set de bloqueio limpo com sucesso.")
            except Exception as e:
                self.logger.error(f"Erro ao limpar set NFTables: {e}")
            self._tracked_ips.clear()
            return
        for ip in list(self._tracked_ips):
            self.unblock(ip)


def get_firewall_manager():
    """Retorna o manager correto baseado no SO."""
    os_name = platform.system().lower()
    if os_name == "windows":
        return WindowsFirewall()
    else:
        return LinuxFirewall()
