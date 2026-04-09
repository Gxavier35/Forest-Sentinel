"""
i18n.py
-------
Módulo de internacionalização do Forest Sentinel.
Suporta PT-BR (padrão) e EN-US.
"""

_LANG = "pt"  # Idioma ativo: "pt" ou "en"

STRINGS = {
    # ── Janela principal ──────────────────────────────────────────────────────
    "app_title":         {"pt": "Forest Sentinel",           "en": "Forest Sentinel"},
    "status_ready":      {"pt": "Status: Pronto",             "en": "Status: Ready"},

    # ── Abas ──────────────────────────────────────────────────────────────────
    "tab_monitor":       {"pt": "🚀 MONITOR",                 "en": "🚀 MONITOR"},
    "tab_config":        {"pt": "⚙ CONFIG",                   "en": "⚙ CONFIG"},
    "tab_blocked":       {"pt": "🔒 BLOQUEADOS",              "en": "🔒 BLOCKED"},
    "tab_whitelist":     {"pt": "🛡 WHITELIST",               "en": "🛡 WHITELIST"},
    "tab_blocked_cnt":   {"pt": "🔒 BLOQUEADOS ({n})",        "en": "🔒 BLOCKED ({n})"},

    # ── Cards de métrica ──────────────────────────────────────────────────────
    "card_active":       {"pt": "Ativos",                     "en": "Active"},
    "card_normal":       {"pt": "Normal",                     "en": "Normal"},
    "card_attacks":      {"pt": "Ataques",                    "en": "Attacks"},
    "card_traffic":      {"pt": "Tráfego",                    "en": "Traffic"},
    "unit_flows":        {"pt": "fluxos",                     "en": "flows"},
    "unit_alerts":       {"pt": "alertas",                    "en": "alerts"},
    "unit_pps":          {"pt": "pps",                        "en": "pps"},

    # ── Tabela principal ──────────────────────────────────────────────────────
    "col_time":          {"pt": "Hora",                       "en": "Time"},
    "col_flow":          {"pt": "Fluxo",                      "en": "Flow"},
    "col_proto":         {"pt": "Proto",                      "en": "Proto"},
    "col_pkts":          {"pt": "Pacotes",                    "en": "Packets"},
    "col_duration":      {"pt": "Duração",                    "en": "Duration"},
    "col_status":        {"pt": "Status",                     "en": "Status"},
    "col_threat":        {"pt": "Nível de Ameaça",            "en": "Threat Level"},

    # ── Labels de status de fluxo ─────────────────────────────────────────────
    "label_attack":      {"pt": "🚨 ATAQUE",                  "en": "🚨 ATTACK"},
    "label_suspicious":  {"pt": "⚠️ POSSÍVEL ATAQUE",         "en": "⚠️ SUSPICIOUS"},
    "label_error":       {"pt": "❌ ERRO IA",                  "en": "❌ AI ERROR"},
    "label_normal":      {"pt": "✅ Normal",                   "en": "✅ Normal"},

    # ── Aba Operação ──────────────────────────────────────────────────────────
    "op_group":          {"pt": "🕹️ Painel de Operação",      "en": "🕹️ Operation Panel"},
    "btn_start":         {"pt": "▶  Iniciar Monitoramento",   "en": "▶  Start Monitoring"},
    "btn_stop":          {"pt": "⏹  Parar",                   "en": "⏹  Stop"},
    "btn_export":        {"pt": "📊  Exportar Ataques (CSV)",  "en": "📊  Export Attacks (CSV)"},
    "btn_clear":         {"pt": "🗑  Limpar",                  "en": "🗑  Clear"},
    "log_group":         {"pt": "📋 Log de Eventos",           "en": "📋 Event Log"},
    "tip_start":         {"pt": "Inicia a captura de pacotes e análise em tempo real (Requer Admin).",
                           "en": "Starts packet capture and real-time analysis (Requires Admin)."},
    "tip_stop":          {"pt": "Interrompe a captura e desliga o motor de análise.",
                           "en": "Stops capture and shuts down the analysis engine."},
    "tip_export":        {"pt": "Exporta o histórico de ataques confirmados para um arquivo CSV.",
                           "en": "Exports confirmed attack history to a CSV file."},
    "tip_clear":         {"pt": "Limpa o console de eventos e o histórico atual da UI.",
                           "en": "Clears the event console and current UI history."},

    # ── Aba Configuração ──────────────────────────────────────────────────────
    "cfg_net_group":     {"pt": "⚙️ Configurações de Rede",   "en": "⚙️ Network Settings"},
    "cfg_iface_lbl":     {"pt": "Interface:",                  "en": "Interface:"},
    "cfg_iface_tip":     {"pt": "Atualizar Interfaces",        "en": "Refresh Interfaces"},
    "cfg_profile_lbl":   {"pt": "Perfil de IA:",              "en": "AI Profile:"},
    "cfg_profile_home":  {"pt": "🏡 Doméstico (Sensível)",     "en": "🏡 Home (Sensitive)"},
    "cfg_profile_pme":   {"pt": "🏢 Comercial/PME (Equilibrado)", "en": "🏢 Business/SMB (Balanced)"},
    "cfg_profile_dc":    {"pt": "🚀 Datacenter (Alta Vazão)",  "en": "🚀 Datacenter (High Throughput)"},
    "cfg_autoblock":     {"pt": "🔒  Bloqueio Automático via Firewall",
                           "en": "🔒  Automatic Firewall Block"},
    "cfg_ai_group":      {"pt": "🧠 Sensibilidade da IA (Isolation Forest)",
                           "en": "🧠 AI Sensitivity (Isolation Forest)"},
    "cfg_reset":         {"pt": "🔄 Restaurar Padrões",        "en": "🔄 Restore Defaults"},
    "cfg_save":          {"pt": "💾 Salvar Configurações",     "en": "💾 Save Settings"},
    "cfg_reset_tip":     {"pt": "Redefine todos os thresholds de IA para os valores originais recomendados.",
                           "en": "Resets all AI thresholds to the original recommended values."},
    "cfg_save_tip":      {"pt": "Aplica permanentemente as configurações desta aba ao motor ativo.",
                           "en": "Permanently applies the settings in this tab to the active engine."},
    "cfg_slider_tip":    {"pt": ("Ajuste da Sensibilidade da IA:\n"
                                  "- Quanto MAIS NEGATIVO (ex: -0.50), MAIS RÍGIDA a detecção (mais alertas).\n"
                                  "- Quanto MAIS POSITIVO (ex: 0.10), MAIS TOLERANTE a detecção (menos falsos-positivos)."),
                           "en": ("AI Sensitivity Adjustment:\n"
                                  "- More NEGATIVE (e.g. -0.50) = STRICTER detection (more alerts).\n"
                                  "- More POSITIVE (e.g. 0.10) = MORE TOLERANT detection (fewer false positives).")},
    "cfg_autoblock_tip": {"pt": "Se ativado, IPs confirmados como ataque serão bloqueados automaticamente via Firewall.",
                           "en": "If enabled, confirmed attack IPs will be automatically blocked via Firewall."},
    "cfg_profile_tip":   {"pt": ("Define a sensibilidade da detecção:\n"
                                  "• Doméstico: Dispara com poucos PPS extras.\n"
                                  "• PME: Tolerância moderada a picos de tráfego.\n"
                                  "• Datacenter: Apenas ataques massivos são bloqueados."),
                           "en": ("Sets detection sensitivity:\n"
                                  "• Home: Triggers with few extra PPS.\n"
                                  "• SMB: Moderate tolerance for traffic spikes.\n"
                                  "• Datacenter: Only massive attacks are blocked.")},

    # ── Aba Bloqueados ────────────────────────────────────────────────────────
    "blk_group":         {"pt": "🔒 IPs Bloqueados via Firewall",
                           "en": "🔒 Firewall-Blocked IPs"},
    "blk_warn":          {"pt": "⚠️  IPs listados abaixo estão bloqueados no Firewall desta sessão.",
                           "en": "⚠️  IPs listed below are blocked in the Firewall for this session."},
    "blk_col_ip":        {"pt": "IP Bloqueado",               "en": "Blocked IP"},
    "blk_col_time":      {"pt": "Horário",                    "en": "Time"},
    "blk_col_pps":       {"pt": "Intensidade (PPS)",          "en": "Intensity (PPS)"},
    "blk_col_action":    {"pt": "Ação",                       "en": "Action"},
    "blk_unblock_all":   {"pt": "🔓  Desbloquear Todos",      "en": "🔓  Unblock All"},
    "blk_unblock_tip":   {"pt": "Remove TODAS as restrições atuais do Firewall e libera os IPs listados.",
                           "en": "Removes ALL current Firewall restrictions and releases listed IPs."},

    # ── Aba Whitelist ─────────────────────────────────────────────────────────
    "wl_group":          {"pt": "🛡️ Whitelist (Exceções de IP/Rede)",
                           "en": "🛡️ Whitelist (IP/Network Exceptions)"},
    "wl_placeholder":    {"pt": "Digite o IP (ex: 192.168.0.50)",
                           "en": "Enter IP (e.g. 192.168.0.50)"},
    "wl_add":            {"pt": "➕ Adicionar",               "en": "➕ Add"},
    "wl_remove":         {"pt": "➖ Remover",                  "en": "➖ Remove"},
    "wl_clear":          {"pt": "🗑️ Limpar Tudo",             "en": "🗑️ Clear All"},
    "wl_add_tip":        {"pt": "Adiciona o IP/Rede acima à lista de confiança (NUNCA será bloqueado).",
                           "en": "Adds the IP/Network above to the trust list (will NEVER be blocked)."},
    "wl_remove_tip":     {"pt": "Remove o item selecionado da Whitelist.",
                           "en": "Removes the selected item from the Whitelist."},
    "wl_clear_tip":      {"pt": "Remove todos os IPs e redes da Whitelist.",
                           "en": "Removes all IPs and networks from the Whitelist."},

    # ── Gráfico ───────────────────────────────────────────────────────────────
    "chart_normal":      {"pt": "Normal",                     "en": "Normal"},
    "chart_attack":      {"pt": "Ataque",                     "en": "Attack"},
    "chart_axis_y":      {"pt": "Fluxos/s",                   "en": "Flows/s"},

    # ── Tray ──────────────────────────────────────────────────────────────────
    "tray_tooltip":      {"pt": "Forest Sentinel — Em execução",
                           "en": "Forest Sentinel — Running"},
    "tray_restore":      {"pt": "🖥  Restaurar Janela",        "en": "🖥  Restore Window"},
    "tray_quit":         {"pt": "✖  Encerrar Monitor",         "en": "✖  Quit Monitor"},
    "tray_bg_title":     {"pt": "Forest Sentinel",            "en": "Forest Sentinel"},
    "tray_bg_msg":       {"pt": ("O monitor continua ativo em segundo plano.\n"
                                  "Clique duas vezes no ícone para restaurar."),
                           "en": ("The monitor is still running in the background.\n"
                                  "Double-click the icon to restore.")},

    # ── Mensagens / Diálogos ──────────────────────────────────────────────────
    "msg_settings_ok":   {"pt": "As configurações de rede e IA foram aplicadas.",
                           "en": "Network and AI settings have been applied."},
    "msg_settings_title":{"pt": "Sucesso",                    "en": "Success"},
    "msg_no_attacks":    {"pt": "Não há eventos de ataque registrados.",
                           "en": "No attack events have been recorded."},
    "msg_export_title":  {"pt": "Exportar",                   "en": "Export"},
    "msg_export_dlg":    {"pt": "Exportar Relatório Histórico", "en": "Export History Report"},
    "msg_wl_clear_title":{"pt": "Limpar Whitelist",           "en": "Clear Whitelist"},
    "msg_wl_clear_q":    {"pt": "Deseja remover TODOS os IPs da Whitelist?",
                           "en": "Do you want to remove ALL IPs from the Whitelist?"},
    "msg_admin_warn":    {"pt": "Execute como Administrador para habilitar captura de pacotes e firewall.",
                           "en": "Run as Administrator to enable packet capture and firewall."},
    "msg_admin_title":   {"pt": "Aviso",                      "en": "Warning"},
    "msg_thresholds_reset":{"pt":"🔄 Thresholds de IA redefinidos.",
                           "en": "🔄 AI thresholds reset."},
    "msg_settings_saved":{"pt": "💾 Configurações aplicadas com sucesso.",
                           "en": "💾 Settings applied successfully."},
    "msg_started":       {"pt": "🚀 Proteção iniciada.",       "en": "🚀 Protection started."},
    "msg_start_fail":    {"pt": "⚠️ Falha ao iniciar. Verifique os logs.",
                           "en": "⚠️ Failed to start. Check the logs."},
    "msg_stopped":       {"pt": "⏹ Proteção interrompida.",   "en": "⏹ Protection stopped."},
    "msg_loaded":        {"pt": "🖥️ Interface carregada.",     "en": "🖥️ Interface loaded."},
    "msg_autoblock_on":  {"pt": "🛡 Bloqueio automático: LIGADO",
                           "en": "🛡 Auto-block: ON"},
    "msg_autoblock_off": {"pt": "🛡 Bloqueio automático: DESLIGADO",
                           "en": "🛡 Auto-block: OFF"},
    "msg_profile":       {"pt": "🧠 Perfil IA: {p}",          "en": "🧠 AI Profile: {p}"},
    "msg_wl_added":      {"pt": "✅ Whitelist: {ip}",          "en": "✅ Whitelist: {ip}"},
    "msg_wl_invalid":    {"pt": "⚠️ IP/Rede inválido: {ip}",   "en": "⚠️ Invalid IP/Network: {ip}"},
    "msg_wl_removed":    {"pt": "🗑 Whitelist removido: {ip}",  "en": "🗑 Whitelist removed: {ip}"},
    "msg_wl_cleared":    {"pt": "🗑 Whitelist totalmente limpa.", "en": "🗑 Whitelist cleared."},
    "msg_fw_cleared":    {"pt": "🔓 Firewall limpo.",           "en": "🔓 Firewall cleared."},
    "msg_export_saved":  {"pt": "📊 Relatório histórico salvo: {path}",
                           "en": "📊 History report saved: {path}"},
    "msg_export_err":    {"pt": "❌ Erro ao exportar: {e}",    "en": "❌ Export error: {e}"},
    "msg_if_autostart":  {"pt": "Procurando interfaces...",    "en": "Searching interfaces..."},
    "msg_if_default":    {"pt": "Adaptador Padrão",            "en": "Default Adapter"},
    "msg_iface_lbl":     {"pt": "Interface:",                  "en": "Interface:"},

    # ── Mensagens de log em tempo real ───────────────────────────────────────
    "log_attack_traffic":{"pt": "🚨 {label}: Tráfego suspeito de {ip}",
                           "en": "🚨 {label}: Suspicious traffic from {ip}"},
    "log_normalized":    {"pt": "✅ Normalizado: Tráfego suspeito de {ip} cessou.",
                           "en": "✅ Normalized: Suspicious traffic from {ip} stopped."},
    "log_blocked":       {"pt": "🚨 BLOQUEADO: {ip} ({pps:.0f} PPS)",
                           "en": "🚨 BLOCKED: {ip} ({pps:.0f} PPS)"},
    "log_unblocked":     {"pt": "🔓 DESBLOQUEADO: {ip}",       "en": "🔓 UNBLOCKED: {ip}"},
    "log_error":         {"pt": "❌ ERRO: {err}",               "en": "❌ ERROR: {err}"},
    "log_blocking_req":  {"pt": "⛔ BLOQUEANDO O TRAFEGO: {ip} ({pps:.0f} pps)",
                           "en": "⛔ BLOCKING TRAFFIC: {ip} ({pps:.0f} pps)"},
    "log_block_tray":    {"pt": "IP {ip} enviado para o Firewall.",
                           "en": "IP {ip} sent to Firewall."},
    "log_block_tray_t":  {"pt": "🛡 Bloqueio",                  "en": "🛡 Block"},
    "log_attack_tray":   {"pt": "Anomalia em {ip}",             "en": "Anomaly at {ip}"},
    "log_status_prefix": {"pt": "Status: {msg}",               "en": "Status: {msg}"},
    "log_status_event":  {"pt": "ℹ️ {msg}",                    "en": "ℹ️ {msg}"},

    # ── Monitor Engine ────────────────────────────────────────────────────────
    "status_model_loaded": {"pt": "✅ Modelo carregado: {m}", "en": "✅ Model loaded: {m}"},
    "status_scaler_loaded": {"pt": "✅ Scaler carregado.", "en": "✅ Scaler loaded."},
    "status_starting": {"pt": "⚙️ {msg}", "en": "⚙️ {msg}"},
    "status_capture_started": {"pt": "🔍 Captura iniciada…", "en": "🔍 Capture started…"},
    "status_connection_lost": {"pt": "⚠️ Conexão perdida. Reconectando…", "en": "⚠️ Connection lost. Reconnecting…"},
    "status_network_fail": {"pt": "⏳ Falha de rede. Tentando em {s}s…", "en": "⏳ Network failure. Retrying in {s}s…"},
    "status_monitoring_stopped": {"pt": "🛑 Monitoramento interrompido.", "en": "🛑 Monitoring stopped."},
    "status_no_traffic": {"pt": "⚠️ Nenhum tráfego detectado. Tente trocar a Interface na aba CONFIG.", "en": "⚠️ No traffic detected. Try changing the Interface in the CONFIG tab."},
    "status_traffic_detected": {"pt": "✅ Tráfego de rede detectado.", "en": "✅ Network traffic detected."},
    "msg_ai_restarting": {"pt": "📦 Motor de IA: Reiniciando...", "en": "📦 AI Engine: Restarting..."},
    "msg_ai_starting": {"pt": "📦 Motor de IA: Iniciando...", "en": "📦 AI Engine: Starting..."},

    # ── AlertBanner ───────────────────────────────────────────────────────────
    "alert_default":     {"pt": "ATAQUE DDOS DETECTADO",        "en": "DDOS ATTACK DETECTED"},
}


def set_lang(lang: str):
    """Define o idioma ativo globalmente. Valores aceitos: 'pt' ou 'en'."""
    global _LANG
    if lang in ("pt", "en"):
        _LANG = lang


def get_lang() -> str:
    return _LANG


def tr(key: str, **kwargs) -> str:
    """
    Retorna a string traduzida para o idioma ativo.
    Suporta placeholders via kwargs: tr('msg_profile', p='home')
    """
    entry = STRINGS.get(key)
    if entry is None:
        return key  # Fallback: retorna a chave
    text = entry.get(_LANG) or entry.get("pt", key)
    if kwargs:
        try:
            text = text.format(**kwargs)
        except KeyError:
            pass
    return text
