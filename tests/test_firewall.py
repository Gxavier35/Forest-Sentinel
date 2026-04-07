import pytest
from unittest.mock import patch, MagicMock
from firewall import is_valid_ip, WindowsFirewall, LinuxFirewall

def test_is_valid_ip():
    # Positivos Reais
    assert is_valid_ip("192.168.1.1") is True
    assert is_valid_ip("8.8.8.8") is True
    assert is_valid_ip("10.0.0.0") is True
    assert is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True

    # Comandos injetados / Formatacoes Invalidas
    assert is_valid_ip("256.256.256.256") is False
    assert is_valid_ip("1.2.3.4 & rm -rf /") is False
    assert is_valid_ip("1.1.1.1 | calc.exe") is False
    assert is_valid_ip("not_an_ip") is False
    assert is_valid_ip("") is False
    assert is_valid_ip(" ") is False

@patch("firewall.subprocess.run")
def test_windows_firewall_block_invalid_ip(mock_run):
    fw = WindowsFirewall()
    assert fw.block("1.2.3.4 & ping google.com") is False
    mock_run.assert_not_called()

@patch("firewall.subprocess.run")
def test_linux_firewall_block_invalid_ip(mock_run):
    fw = LinuxFirewall()
    assert fw.block("invalid_ip") is False
    mock_run.assert_not_called()

@patch("firewall.is_admin", return_value=True)
@patch("firewall.subprocess.run")
def test_windows_firewall_block_valid_ip(mock_run, mock_admin):
    # Simula status de netsh onde regra nao existe (1), dps sucesso no add (0), dps verificacao (0)
    mock_process = MagicMock()
    mock_process.returncode = 1 
    
    mock_process_add = MagicMock()
    mock_process_add.returncode = 0 
    
    mock_process_verify = MagicMock()
    mock_process_verify.stdout = "Rule Name: DDoS_Block_8.8.8.8"
    mock_process_verify.returncode = 0
    
    # Preenche o sub-processador com sequencia otimista do Windows
    mock_run.side_effect = [mock_process, mock_process_add, mock_process_verify]
    
    fw = WindowsFirewall()
    res = fw.block("8.8.8.8")
    
    assert res is True
    assert "8.8.8.8" in fw._tracked_ips
    assert mock_run.call_count == 3
