#!/usr/bin/env python3
"""
Strix PyQt6 可视化作战中心 (War Room Client)

一个独立的 PyQt6 前端客户端，通过 WebSocket 连接 Strix 后端，
实时展示资产树、漏洞发现和 AI 推理过程。

依赖安装:
    pip install PyQt6 websockets markdown

运行:
    python gui_client.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from PyQt6.QtCore import (
    Qt,
    QTimer,
    QThread,
    pyqtSignal,
    pyqtSlot,
)
from PyQt6.QtGui import (
    QColor,
    QFont,
    QIcon,
    QPalette,
    QTextCharFormat,
    QBrush,
)
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QTextEdit,
    QLineEdit,
    QPushButton,
    QLabel,
    QStatusBar,
    QGroupBox,
    QTabWidget,
    QListWidget,
    QListWidgetItem,
    QFrame,
    QProgressBar,
    QMessageBox,
)

# Optional: Markdown rendering
try:
    import markdown
    HAS_MARKDOWN = True
except ImportError:
    HAS_MARKDOWN = False
    print("提示: 安装 'markdown' 库可获得更好的 AI 推理过程渲染效果")

# WebSocket library
try:
    import websockets
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False
    print("错误: 请安装 'websockets' 库: pip install websockets")


# === 颜色主题 (暗色) ===
class Theme:
    BG_DARK = "#1e1e2e"
    BG_MEDIUM = "#2d2d3d"
    BG_LIGHT = "#3d3d4d"
    FG_PRIMARY = "#cdd6f4"
    FG_SECONDARY = "#a6adc8"
    ACCENT_BLUE = "#89b4fa"
    ACCENT_GREEN = "#a6e3a1"
    ACCENT_RED = "#f38ba8"
    ACCENT_YELLOW = "#f9e2af"
    ACCENT_PURPLE = "#cba6f7"
    ACCENT_ORANGE = "#fab387"


# === 事件类型映射 ===
class EventIcons:
    SCAN_STARTED = "🚀"
    SCAN_COMPLETED = "✅"
    VULNERABILITY = "🔴"
    PHASE = "📋"
    PLUGIN = "🔌"
    AI_THOUGHT = "🧠"
    WARNING = "⚠️"
    ERROR = "❌"
    INFO = "ℹ️"


# === WebSocket 客户端线程 ===
class WebSocketThread(QThread):
    """后台线程处理 WebSocket 连接"""
    
    # 信号
    connected = pyqtSignal()
    disconnected = pyqtSignal()
    message_received = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, url: str, client_id: str):
        super().__init__()
        self.url = url
        self.client_id = client_id
        self._running = False
        self._websocket = None
    
    def run(self):
        """线程主循环"""
        self._running = True
        asyncio.run(self._connect_and_listen())
    
    async def _connect_and_listen(self):
        """连接并监听消息"""
        full_url = f"{self.url}/{self.client_id}"
        
        try:
            async with websockets.connect(full_url) as ws:
                self._websocket = ws
                self.connected.emit()
                
                while self._running:
                    try:
                        message = await asyncio.wait_for(ws.recv(), timeout=1.0)
                        data = json.loads(message)
                        self.message_received.emit(data)
                    except asyncio.TimeoutError:
                        continue
                    except websockets.ConnectionClosed:
                        break
                        
        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            self.disconnected.emit()
    
    def stop(self):
        """停止线程"""
        self._running = False
        self.wait()
    
    def send_message(self, message: dict):
        """发送消息到服务器"""
        if self._websocket:
            asyncio.run(self._websocket.send(json.dumps(message)))


# === AI 神经日志面板 ===
class NeuralLogPanel(QWidget):
    """AI 思维透视面板 - 展示 reasoning_trace"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # 标题
        title_label = QLabel("🧠 AI Neural Log")
        title_label.setStyleSheet(f"""
            font-size: 16px;
            font-weight: bold;
            color: {Theme.ACCENT_PURPLE};
            padding: 10px;
            background-color: {Theme.BG_MEDIUM};
            border-radius: 5px;
        """)
        layout.addWidget(title_label)
        
        # TabWidget 分离不同类型的日志
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {Theme.BG_LIGHT};
                background-color: {Theme.BG_DARK};
            }}
            QTabBar::tab {{
                background-color: {Theme.BG_MEDIUM};
                color: {Theme.FG_SECONDARY};
                padding: 8px 16px;
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{
                background-color: {Theme.ACCENT_PURPLE};
                color: white;
            }}
        """)
        
        # 推理过程 Tab
        self.reasoning_view = QTextEdit()
        self.reasoning_view.setReadOnly(True)
        self.reasoning_view.setStyleSheet(f"""
            QTextEdit {{
                background-color: {Theme.BG_DARK};
                color: {Theme.FG_PRIMARY};
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 13px;
                border: none;
                padding: 10px;
            }}
        """)
        self.tabs.addTab(self.reasoning_view, "推理过程")
        
        # 证据 Tab
        self.evidence_view = QListWidget()
        self.evidence_view.setStyleSheet(f"""
            QListWidget {{
                background-color: {Theme.BG_DARK};
                color: {Theme.FG_PRIMARY};
                border: none;
            }}
            QListWidget::item {{
                padding: 8px;
                border-bottom: 1px solid {Theme.BG_LIGHT};
            }}
            QListWidget::item:selected {{
                background-color: {Theme.ACCENT_BLUE};
            }}
        """)
        self.tabs.addTab(self.evidence_view, "证据列表")
        
        # 验证任务 Tab
        self.verification_view = QListWidget()
        self.verification_view.setStyleSheet(self.evidence_view.styleSheet())
        self.tabs.addTab(self.verification_view, "验证任务")
        
        layout.addWidget(self.tabs)
    
    def add_reasoning_trace(self, vuln_type: str, reasoning_trace: str, 
                            confidence: float, is_vulnerable: bool):
        """添加一条 AI 推理记录"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # 状态图标
        status = "🔴 VULNERABLE" if is_vulnerable else "🟢 SAFE"
        
        # 构建 HTML
        header = f"""
        <div style="background-color: {Theme.BG_MEDIUM}; padding: 10px; 
                    border-left: 4px solid {Theme.ACCENT_PURPLE if is_vulnerable else Theme.ACCENT_GREEN};
                    margin-bottom: 15px;">
            <span style="color: {Theme.FG_SECONDARY};">[{timestamp}]</span>
            <span style="color: {Theme.ACCENT_BLUE}; font-weight: bold;">{vuln_type.upper()}</span>
            <span style="color: {Theme.ACCENT_YELLOW};">置信度: {confidence*100:.0f}%</span>
            <span>{status}</span>
        </div>
        """
        
        # 渲染 Markdown
        if HAS_MARKDOWN and reasoning_trace:
            body = markdown.markdown(reasoning_trace, extensions=['fenced_code', 'tables'])
        else:
            body = f"<pre>{reasoning_trace}</pre>"
        
        content = header + body + "<hr style='border-color: " + Theme.BG_LIGHT + ";'/>"
        
        # 追加到视图
        self.reasoning_view.append(content)
        
        # 滚动到底部
        scrollbar = self.reasoning_view.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def add_evidence(self, evidence: list[str], evidence_snippet: str):
        """添加证据"""
        for e in evidence:
            item = QListWidgetItem(f"📌 {e}")
            item.setForeground(QColor(Theme.ACCENT_GREEN))
            self.evidence_view.addItem(item)
        
        if evidence_snippet:
            item = QListWidgetItem(f"🔍 响应片段:\n{evidence_snippet[:200]}...")
            item.setForeground(QColor(Theme.ACCENT_YELLOW))
            self.evidence_view.addItem(item)
    
    def add_verification_task(self, task_id: str, payload: str, reason: str):
        """添加验证任务"""
        item = QListWidgetItem(f"🔄 [{task_id}] {reason}\n    Payload: {payload[:50]}...")
        item.setForeground(QColor(Theme.ACCENT_ORANGE))
        self.verification_view.addItem(item)


# === 资产树面板 ===
class AssetTreePanel(QWidget):
    """左侧资产树 - 实时展示发现的资产和漏洞"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.asset_items: dict[str, QTreeWidgetItem] = {}
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # 标题
        title_label = QLabel("🌐 资产 & 漏洞")
        title_label.setStyleSheet(f"""
            font-size: 16px;
            font-weight: bold;
            color: {Theme.ACCENT_BLUE};
            padding: 10px;
            background-color: {Theme.BG_MEDIUM};
            border-radius: 5px;
        """)
        layout.addWidget(title_label)
        
        # 树形视图
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["资产/漏洞", "状态", "置信度"])
        self.tree.setStyleSheet(f"""
            QTreeWidget {{
                background-color: {Theme.BG_DARK};
                color: {Theme.FG_PRIMARY};
                border: none;
            }}
            QTreeWidget::item {{
                padding: 5px;
            }}
            QTreeWidget::item:selected {{
                background-color: {Theme.ACCENT_BLUE};
            }}
            QHeaderView::section {{
                background-color: {Theme.BG_MEDIUM};
                color: {Theme.FG_PRIMARY};
                padding: 5px;
                border: none;
            }}
        """)
        self.tree.setColumnWidth(0, 250)
        self.tree.setColumnWidth(1, 80)
        layout.addWidget(self.tree)
    
    def add_scan(self, scan_id: str, target: str):
        """添加新扫描节点"""
        item = QTreeWidgetItem([f"🎯 {target}", "扫描中", ""])
        item.setForeground(0, QColor(Theme.ACCENT_BLUE))
        self.tree.addTopLevelItem(item)
        self.asset_items[scan_id] = item
        item.setExpanded(True)
        return item
    
    def add_phase(self, scan_id: str, phase: str):
        """添加扫描阶段"""
        parent = self.asset_items.get(scan_id)
        if parent:
            phase_item = QTreeWidgetItem([f"📋 {phase}", "进行中", ""])
            phase_item.setForeground(0, QColor(Theme.ACCENT_YELLOW))
            parent.addChild(phase_item)
            self.asset_items[f"{scan_id}_{phase}"] = phase_item
            phase_item.setExpanded(True)
    
    def add_vulnerability(self, scan_id: str, vuln_type: str, target: str, 
                          confidence: float, severity: str):
        """添加发现的漏洞"""
        parent = self.asset_items.get(scan_id)
        if parent:
            # 根据严重程度设置颜色
            severity_colors = {
                "critical": Theme.ACCENT_RED,
                "high": Theme.ACCENT_ORANGE,
                "medium": Theme.ACCENT_YELLOW,
                "low": Theme.ACCENT_GREEN,
            }
            color = severity_colors.get(severity.lower(), Theme.FG_PRIMARY)
            
            vuln_item = QTreeWidgetItem([
                f"🔴 {vuln_type}: {target[:30]}...",
                severity.upper(),
                f"{confidence*100:.0f}%"
            ])
            vuln_item.setForeground(0, QColor(color))
            vuln_item.setForeground(1, QColor(color))
            parent.addChild(vuln_item)
    
    def mark_scan_completed(self, scan_id: str, status: str):
        """标记扫描完成"""
        item = self.asset_items.get(scan_id)
        if item:
            item.setText(1, status)
            if status == "完成":
                item.setForeground(1, QColor(Theme.ACCENT_GREEN))
            elif status == "失败":
                item.setForeground(1, QColor(Theme.ACCENT_RED))


# === 事件日志面板 ===
class EventLogPanel(QWidget):
    """底部事件日志"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.log_view = QListWidget()
        self.log_view.setStyleSheet(f"""
            QListWidget {{
                background-color: {Theme.BG_DARK};
                color: {Theme.FG_PRIMARY};
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 12px;
                border: none;
            }}
            QListWidget::item {{
                padding: 4px;
                border-bottom: 1px solid {Theme.BG_LIGHT};
            }}
        """)
        self.log_view.setMaximumHeight(150)
        layout.addWidget(self.log_view)
    
    def add_log(self, event_type: str, message: str, level: str = "info"):
        """添加日志条目"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        icon_map = {
            "scan.started": EventIcons.SCAN_STARTED,
            "scan.completed": EventIcons.SCAN_COMPLETED,
            "vulnerability.found": EventIcons.VULNERABILITY,
            "phase.started": EventIcons.PHASE,
            "plugin.started": EventIcons.PLUGIN,
            "error": EventIcons.ERROR,
        }
        icon = icon_map.get(event_type, EventIcons.INFO)
        
        item = QListWidgetItem(f"[{timestamp}] {icon} {event_type}: {message}")
        
        # 根据级别设置颜色
        if level == "error":
            item.setForeground(QColor(Theme.ACCENT_RED))
        elif level == "warning":
            item.setForeground(QColor(Theme.ACCENT_YELLOW))
        elif "vulnerability" in event_type:
            item.setForeground(QColor(Theme.ACCENT_RED))
        else:
            item.setForeground(QColor(Theme.FG_SECONDARY))
        
        self.log_view.addItem(item)
        self.log_view.scrollToBottom()


# === 主窗口 ===
class StrixWarRoom(QMainWindow):
    """Strix 可视化作战中心主窗口"""
    
    def __init__(self):
        super().__init__()
        self.ws_thread: WebSocketThread | None = None
        self.client_id = str(uuid.uuid4())[:8]
        self.setup_ui()
        self.apply_theme()
    
    def setup_ui(self):
        self.setWindowTitle("🦉 Strix War Room - AI 安全作战中心")
        self.setMinimumSize(1400, 900)
        
        # 中央 Widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # === 顶部连接栏 ===
        conn_bar = QFrame()
        conn_bar.setStyleSheet(f"""
            QFrame {{
                background-color: {Theme.BG_MEDIUM};
                border-radius: 8px;
                padding: 5px;
            }}
        """)
        conn_layout = QHBoxLayout(conn_bar)
        
        conn_layout.addWidget(QLabel("🔗 后端地址:"))
        
        self.url_input = QLineEdit("ws://localhost:8000/ws")
        self.url_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {Theme.BG_DARK};
                color: {Theme.FG_PRIMARY};
                border: 1px solid {Theme.BG_LIGHT};
                border-radius: 4px;
                padding: 8px;
                font-size: 14px;
            }}
        """)
        self.url_input.setMinimumWidth(300)
        conn_layout.addWidget(self.url_input)
        
        self.connect_btn = QPushButton("🚀 连接")
        self.connect_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {Theme.ACCENT_GREEN};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 20px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #8ed993;
            }}
            QPushButton:disabled {{
                background-color: {Theme.BG_LIGHT};
            }}
        """)
        self.connect_btn.clicked.connect(self.toggle_connection)
        conn_layout.addWidget(self.connect_btn)
        
        self.status_indicator = QLabel("⚪ 未连接")
        self.status_indicator.setStyleSheet(f"color: {Theme.FG_SECONDARY};")
        conn_layout.addWidget(self.status_indicator)
        
        conn_layout.addStretch()
        
        # 扫描统计
        self.stats_label = QLabel("漏洞: 0 | 扫描: 0 | LLM 调用: 0")
        self.stats_label.setStyleSheet(f"color: {Theme.ACCENT_YELLOW};")
        conn_layout.addWidget(self.stats_label)
        
        main_layout.addWidget(conn_bar)
        
        # === 主内容区 ===
        content_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # 左侧: 资产树
        self.asset_panel = AssetTreePanel()
        self.asset_panel.setMinimumWidth(350)
        content_splitter.addWidget(self.asset_panel)
        
        # 右侧: AI Neural Log
        self.neural_panel = NeuralLogPanel()
        content_splitter.addWidget(self.neural_panel)
        
        content_splitter.setSizes([350, 800])
        main_layout.addWidget(content_splitter, 1)
        
        # === 底部: 事件日志 ===
        self.event_log = EventLogPanel()
        main_layout.addWidget(self.event_log)
        
        # 状态栏
        self.statusBar().showMessage("就绪 - 点击「连接」开始监控")
    
    def apply_theme(self):
        """应用暗色主题"""
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {Theme.BG_DARK};
            }}
            QWidget {{
                color: {Theme.FG_PRIMARY};
            }}
            QLabel {{
                color: {Theme.FG_PRIMARY};
            }}
            QStatusBar {{
                background-color: {Theme.BG_MEDIUM};
                color: {Theme.FG_SECONDARY};
            }}
            QSplitter::handle {{
                background-color: {Theme.BG_LIGHT};
            }}
        """)
    
    def toggle_connection(self):
        """切换连接状态"""
        if self.ws_thread and self.ws_thread.isRunning():
            self.disconnect_ws()
        else:
            self.connect_ws()
    
    def connect_ws(self):
        """连接 WebSocket"""
        if not HAS_WEBSOCKETS:
            QMessageBox.critical(self, "错误", "请安装 websockets 库: pip install websockets")
            return
        
        url = self.url_input.text().strip()
        if not url:
            return
        
        self.ws_thread = WebSocketThread(url, self.client_id)
        self.ws_thread.connected.connect(self.on_connected)
        self.ws_thread.disconnected.connect(self.on_disconnected)
        self.ws_thread.message_received.connect(self.on_message)
        self.ws_thread.error_occurred.connect(self.on_error)
        self.ws_thread.start()
        
        self.connect_btn.setEnabled(False)
        self.status_indicator.setText("🟡 连接中...")
    
    def disconnect_ws(self):
        """断开 WebSocket"""
        if self.ws_thread:
            self.ws_thread.stop()
            self.ws_thread = None
    
    @pyqtSlot()
    def on_connected(self):
        """连接成功"""
        self.status_indicator.setText("🟢 已连接")
        self.status_indicator.setStyleSheet(f"color: {Theme.ACCENT_GREEN};")
        self.connect_btn.setText("❌ 断开")
        self.connect_btn.setEnabled(True)
        self.connect_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {Theme.ACCENT_RED};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 20px;
                font-weight: bold;
            }}
        """)
        self.statusBar().showMessage(f"已连接到 Strix 后端 (Client ID: {self.client_id})")
        self.event_log.add_log("connected", "成功连接到 Strix 后端")
    
    @pyqtSlot()
    def on_disconnected(self):
        """断开连接"""
        self.status_indicator.setText("⚪ 未连接")
        self.status_indicator.setStyleSheet(f"color: {Theme.FG_SECONDARY};")
        self.connect_btn.setText("🚀 连接")
        self.connect_btn.setEnabled(True)
        self.connect_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {Theme.ACCENT_GREEN};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 20px;
                font-weight: bold;
            }}
        """)
        self.statusBar().showMessage("已断开连接")
        self.event_log.add_log("disconnected", "与 Strix 后端断开连接", "warning")
    
    @pyqtSlot(str)
    def on_error(self, error: str):
        """连接错误"""
        self.status_indicator.setText("🔴 错误")
        self.status_indicator.setStyleSheet(f"color: {Theme.ACCENT_RED};")
        self.connect_btn.setEnabled(True)
        self.event_log.add_log("error", error, "error")
        QMessageBox.warning(self, "连接错误", f"无法连接到服务器:\n{error}")
    
    @pyqtSlot(dict)
    def on_message(self, message: dict):
        """处理接收到的 WebSocket 消息"""
        msg_type = message.get("type", "")
        data = message.get("data", {})
        
        # 添加到事件日志
        summary = str(data)[:100] + "..." if len(str(data)) > 100 else str(data)
        self.event_log.add_log(msg_type, summary)
        
        # 处理不同类型的消息
        if msg_type == "scan.started":
            scan_id = data.get("scan_id", "unknown")
            target = data.get("target", "unknown")
            self.asset_panel.add_scan(scan_id, target)
        
        elif msg_type == "phase.started":
            scan_id = data.get("scan_id")
            phase = data.get("phase", "unknown")
            self.asset_panel.add_phase(scan_id, phase)
        
        elif msg_type == "vulnerability.found":
            scan_id = data.get("scan_id")
            vuln_type = data.get("vuln_type", "unknown")
            target = data.get("target", "")
            confidence = data.get("confidence_score", 0.0)
            severity = data.get("severity", "medium")
            
            # 添加到资产树
            self.asset_panel.add_vulnerability(
                scan_id, vuln_type, target, confidence, severity
            )
            
            # AI 推理过程 (核心功能)
            reasoning_trace = data.get("reasoning_trace", "")
            reasoning = data.get("reasoning", "")
            is_vulnerable = data.get("is_vulnerable", True)
            
            if reasoning_trace or reasoning:
                self.neural_panel.add_reasoning_trace(
                    vuln_type,
                    reasoning_trace or reasoning,
                    confidence,
                    is_vulnerable
                )
            
            # 证据
            evidence = data.get("evidence", [])
            evidence_snippet = data.get("evidence_snippet", "")
            if evidence or evidence_snippet:
                self.neural_panel.add_evidence(evidence, evidence_snippet)
        
        elif msg_type == "scan.completed":
            scan_id = data.get("scan_id")
            self.asset_panel.mark_scan_completed(scan_id, "完成")
        
        elif msg_type == "scan.failed" or msg_type == "scan.error":
            scan_id = data.get("scan_id")
            self.asset_panel.mark_scan_completed(scan_id, "失败")
        
        # LLM 相关事件 (如果后端发送)
        elif msg_type == "llm.response":
            reasoning = data.get("reasoning", "")
            reasoning_trace = data.get("reasoning_trace", "")
            confidence = data.get("confidence_score", 0.5)
            vuln_type = data.get("vuln_type", "analysis")
            is_vulnerable = data.get("is_vulnerable", False)
            
            if reasoning_trace or reasoning:
                self.neural_panel.add_reasoning_trace(
                    vuln_type,
                    reasoning_trace or reasoning,
                    confidence,
                    is_vulnerable
                )
        
        # 验证任务事件 (如果后端发送)
        elif msg_type == "verification.created":
            task_id = data.get("task_id", "")
            payload = data.get("verification_payload", "")
            reason = data.get("reason", "")
            self.neural_panel.add_verification_task(task_id, payload, reason)
    
    def closeEvent(self, event):
        """窗口关闭时清理"""
        self.disconnect_ws()
        event.accept()


# === 主入口 ===
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # 设置应用级暗色调色板
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(Theme.BG_DARK))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(Theme.FG_PRIMARY))
    palette.setColor(QPalette.ColorRole.Base, QColor(Theme.BG_DARK))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(Theme.BG_MEDIUM))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(Theme.BG_LIGHT))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(Theme.FG_PRIMARY))
    palette.setColor(QPalette.ColorRole.Text, QColor(Theme.FG_PRIMARY))
    palette.setColor(QPalette.ColorRole.Button, QColor(Theme.BG_MEDIUM))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(Theme.FG_PRIMARY))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(Theme.ACCENT_BLUE))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("white"))
    app.setPalette(palette)
    
    window = StrixWarRoom()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
