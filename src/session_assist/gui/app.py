"""Qt application shell, dialogs, workers, and managed FreeRDP process launches."""

from __future__ import annotations

import shutil
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Any, Callable

from session_assist.models import AssistPermissionMode, AssistanceError, AuthenticationMode, ShadowControl, ShadowPolicyStatus
from session_assist.services.authentication import KerberosAcquireResult, KerberosService, KerberosStatus, KerberosStatusKind
from session_assist.services.assistance import write_private_invitation
from session_assist.services.rdp import invitation_command, normal_rdp_command
from session_assist.storage import Settings, Storage
from session_assist.gui.controller import BackendController, CheckResult, UiCapabilities, policy_capabilities


try:
    from PySide6.QtCore import QObject, QProcess, QThread, Qt, QTimer, QUrl, Signal, Slot
    from PySide6.QtGui import QAction, QDesktopServices, QIcon
    from PySide6.QtWidgets import (
        QApplication, QButtonGroup, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
        QFileDialog, QFormLayout, QFrame, QGridLayout, QGroupBox, QHBoxLayout, QLabel,
        QMainWindow, QMessageBox, QPushButton, QRadioButton, QScrollArea, QSpinBox,
        QStyle, QTabWidget, QTextEdit, QToolButton, QVBoxLayout, QWidget, QListWidget,
        QListWidgetItem, QLineEdit, QMenu, QInputDialog,
    )
except ImportError as exc:  # Keep the Phase 1 CLI importable without Qt installed.
    PYSIDE_ERROR = exc
else:
    PYSIDE_ERROR = None


if PYSIDE_ERROR is None:
    class TaskWorker(QObject):
        progress = Signal(object, str, object)
        completed = Signal(object)
        failed = Signal(str, str)
        done = Signal()

        def __init__(self, task: Callable[[Callable[..., None]], Any]) -> None:
            super().__init__()
            self.task = task

        @Slot()
        def run(self) -> None:
            try:
                self.completed.emit(self.task(lambda stage, message, detail=None: self.progress.emit(stage, message, detail)))
            except Exception as error:
                self.failed.emit(str(error) or type(error).__name__, traceback.format_exc())
            finally:
                self.done.emit()


    class WorkerCallbackProxy(QObject):
        """Deliver worker signals on the GUI thread, even for Python lambdas."""

        def __init__(
            self, completed: Callable[[Any], None], failed: Callable[[str, str], None],
            progress: Callable[[object, str, object], None] | None, error_reporter: Callable[[str, str], None],
            parent: QObject,
        ) -> None:
            super().__init__(parent)
            self._completed = completed
            self._failed = failed
            self._progress = progress
            self._error_reporter = error_reporter

        def _invoke(self, callback: Callable[..., None], *args: object) -> None:
            try:
                callback(*args)
            except Exception:
                self._error_reporter("GUI callback failed", traceback.format_exc())

        @Slot(object)
        def handle_completed(self, value: object) -> None:
            self._invoke(self._completed, value)

        @Slot(str, str)
        def handle_failed(self, message: str, details: str) -> None:
            self._invoke(self._failed, message, details)

        @Slot(object, str, object)
        def handle_progress(self, stage: object, message: str, detail: object) -> None:
            if self._progress is not None:
                self._invoke(self._progress, stage, message, detail)


    class ProgressDialog(QDialog):
        def __init__(self, title: str, parent: QWidget | None = None) -> None:
            super().__init__(parent)
            self.setWindowTitle(title)
            self.setModal(False)
            self.resize(520, 330)
            layout = QVBoxLayout(self)
            self.heading = QLabel(title)
            self.heading.setStyleSheet("font-weight: 600;")
            self.output = QTextEdit(readOnly=True)
            self.output.setMinimumHeight(210)
            self.details_button = QPushButton("Details")
            self.close_button = QPushButton("Close")
            self.close_button.setEnabled(False)
            row = QHBoxLayout()
            row.addWidget(self.details_button)
            row.addStretch()
            row.addWidget(self.close_button)
            layout.addWidget(self.heading)
            layout.addWidget(self.output)
            layout.addLayout(row)
            self.details_button.clicked.connect(lambda: self.output.setVisible(not self.output.isVisible()))
            self.close_button.clicked.connect(self.accept)

        def add_event(self, stage: object, message: str, detail: object) -> None:
            marker = {"ok": "✓", "wait": "…", "error": "✗", "info": "•"}.get(str(getattr(stage, "value", stage)), "•")
            self.output.append(f"{marker} {message}")
            if detail:
                self.output.append(f"    {detail}")
            self.output.verticalScrollBar().setValue(self.output.verticalScrollBar().maximum())

        def finish(self, heading: str = "Complete") -> None:
            self.heading.setText(heading)
            self.close_button.setEnabled(True)


    class AssistDialog(QDialog):
        def __init__(self, result: CheckResult, settings: Settings, parent: QWidget | None = None) -> None:
            super().__init__(parent)
            self.result = result
            self.capabilities: UiCapabilities = policy_capabilities(result.policy, result.console)
            console = result.console
            if console is None:
                raise AssistanceError("No active physical console session is available.")
            self.setWindowTitle(f"Assist {console.account_name}")
            self.setMinimumWidth(485)
            layout = QVBoxLayout(self)
            title = QLabel(f"Assist {console.account_name}")
            title.setStyleSheet("font-size: 18px; font-weight: 600;")
            detail = QLabel(f"{result.target} • Console • Session ID {console.session_id}")
            detail.setWordWrap(True)
            layout.addWidget(title)
            layout.addWidget(detail)
            policy_box = QGroupBox("Remote Assistance Policy")
            policy_layout = QVBoxLayout(policy_box)
            policy = QLabel(result.policy.friendly_name)
            policy.setStyleSheet("font-weight: 600;")
            policy_layout.addWidget(policy)
            policy_layout.addWidget(QLabel(self.capabilities.reason or "Windows policy determines the available connection modes."))
            layout.addWidget(policy_box)

            permission_box = QGroupBox("Connection permission")
            permission_layout = QVBoxLayout(permission_box)
            self.automatic = QRadioButton("Automatic (Recommended)")
            self.consent = QRadioButton("Ask user for permission")
            self.no_consent = QRadioButton("Connect without prompting")
            self.automatic.setChecked(settings.assist_permission_mode == "auto")
            self.consent.setChecked(settings.assist_permission_mode == "consent")
            self.no_consent.setChecked(settings.assist_permission_mode == "no-consent" and self.capabilities.no_consent_enabled)
            if not any(button.isChecked() for button in (self.automatic, self.consent, self.no_consent)):
                self.automatic.setChecked(True)
            self.no_consent.setEnabled(self.capabilities.no_consent_enabled)
            self.no_consent.setToolTip("Available only when the detected Windows policy conclusively permits it.")
            for button in (self.automatic, self.consent, self.no_consent):
                permission_layout.addWidget(button)
            layout.addWidget(permission_box)

            interaction_box = QGroupBox("Interaction")
            interaction_layout = QVBoxLayout(interaction_box)
            self.control = QRadioButton("Full keyboard and mouse control")
            self.view = QRadioButton("View only")
            self.control.setChecked(True)
            self.control.setEnabled(self.capabilities.full_control_enabled)
            self.view.setEnabled(self.capabilities.view_only_enabled)
            if not self.capabilities.full_control_enabled:
                self.view.setChecked(True)
            interaction_layout.addWidget(self.control)
            interaction_layout.addWidget(self.view)
            layout.addWidget(interaction_box)
            buttons = QDialogButtonBox(QDialogButtonBox.Cancel | QDialogButtonBox.Ok)
            buttons.button(QDialogButtonBox.Ok).setText("Connect")
            buttons.accepted.connect(self.accept)
            buttons.rejected.connect(self.reject)
            layout.addWidget(buttons)

        @property
        def permission(self) -> AssistPermissionMode:
            if self.consent.isChecked():
                return AssistPermissionMode.CONSENT
            if self.no_consent.isChecked():
                return AssistPermissionMode.NO_CONSENT
            return AssistPermissionMode.AUTOMATIC

        @property
        def interaction(self) -> ShadowControl:
            return ShadowControl.VIEW if self.view.isChecked() else ShadowControl.FULL_CONTROL


    class SettingsDialog(QDialog):
        def __init__(self, storage: Storage, controller: BackendController, result: CheckResult | None, parent: QWidget | None = None) -> None:
            super().__init__(parent)
            self.storage = storage
            self.controller = controller
            self.result = result
            self.settings = storage.load_settings()
            self.setWindowTitle("Remote Control Settings")
            self.resize(500, 390)
            layout = QVBoxLayout(self)
            tabs = QTabWidget()
            layout.addWidget(tabs)
            general = QWidget()
            form = QFormLayout(general)
            self.default_permission = QComboBox()
            self.default_permission.addItem("Automatic", "auto")
            self.default_permission.addItem("Always request approval", "consent")
            self.default_permission.addItem("Use native no-prompt mode when permitted", "no-consent")
            index = self.default_permission.findData(self.settings.assist_permission_mode)
            self.default_permission.setCurrentIndex(max(0, index))
            self.max_recents = QSpinBox()
            self.max_recents.setRange(1, 50)
            self.max_recents.setValue(self.settings.max_recent_computers)
            form.addRow("Default Assist permission:", self.default_permission)
            form.addRow("Maximum recent computers:", self.max_recents)
            tabs.addTab(general, "General")
            rdp = QWidget()
            rdp_form = QFormLayout(rdp)
            self.dynamic = QCheckBox("Dynamic resolution")
            self.clipboard = QCheckBox("Clipboard")
            self.audio = QCheckBox("Audio")
            self.dynamic.setChecked(self.settings.rdp_dynamic_resolution)
            self.clipboard.setChecked(self.settings.rdp_clipboard)
            self.audio.setChecked(self.settings.rdp_audio)
            detected = "Not yet detected"
            if result and result.freerdp:
                detected = f"{result.freerdp.executable} ({result.freerdp.version})"
            self.freerdp = QLabel(detected)
            self.freerdp.setTextInteractionFlags(Qt.TextSelectableByMouse)
            rdp_form.addRow("Detected FreeRDP:", self.freerdp)
            rdp_form.addRow(self.dynamic)
            rdp_form.addRow(self.clipboard)
            rdp_form.addRow(self.audio)
            tabs.addTab(rdp, "Remote Desktop")
            auth = QWidget()
            auth_form = QFormLayout(auth)
            self.principal = QLabel("Checking on next operation")
            self.refresh_auth = QPushButton("Refresh Status")
            auth_form.addRow("Kerberos principal:", self.principal)
            auth_form.addRow(self.refresh_auth)
            self.refresh_auth.clicked.connect(self._refresh_auth)
            tabs.addTab(auth, "Authentication")
            diagnostics = QWidget()
            diagnostics_form = QFormLayout(diagnostics)
            self.detailed = QCheckBox("Detailed logging")
            self.detailed.setChecked(self.settings.detailed_logging)
            self.log_path = QLabel(str(storage.log_dir))
            self.log_path.setTextInteractionFlags(Qt.TextSelectableByMouse)
            self.open_logs = QPushButton("Open Log Directory")
            diagnostics_form.addRow(self.detailed)
            diagnostics_form.addRow("Log directory:", self.log_path)
            diagnostics_form.addRow(self.open_logs)
            self.open_logs.clicked.connect(self._open_logs)
            tabs.addTab(diagnostics, "Diagnostics")
            directory = QWidget()
            directory_form = QFormLayout(directory)
            self.ldap_server = QLineEdit(self.settings.ldap_server)
            self.ldap_base = QLineEdit(self.settings.ldap_search_base)
            self.ldap_server.setPlaceholderText("Automatic (DNS SRV / Kerberos realm)")
            self.ldap_base.setPlaceholderText("Automatic (entire domain / RootDSE)")
            directory_form.addRow("LDAP server override:", self.ldap_server)
            directory_form.addRow("Search base / OU:", self.ldap_base)
            directory_form.addRow(QLabel("Directory queries use the current Kerberos cache and never store an LDAP password."))
            tabs.addTab(directory, "Active Directory")
            buttons = QDialogButtonBox(QDialogButtonBox.Cancel | QDialogButtonBox.Save)
            buttons.accepted.connect(self._save)
            buttons.rejected.connect(self.reject)
            layout.addWidget(buttons)

            self._auth_threads: list[QThread] = []
            self._auth_workers: list[TaskWorker] = []

        def _refresh_auth(self) -> None:
            self.refresh_auth.setEnabled(False)
            thread = QThread(self)
            worker = TaskWorker(lambda _progress: self.controller.kerberos_service.get_status())
            worker.moveToThread(thread)
            thread.started.connect(worker.run)
            worker.completed.connect(self._set_auth_status)
            worker.failed.connect(lambda message, _details: self.principal.setText(message))
            worker.done.connect(thread.quit)
            worker.done.connect(worker.deleteLater)
            thread.finished.connect(thread.deleteLater)
            thread.finished.connect(lambda: self._auth_threads.remove(thread) if thread in self._auth_threads else None)
            thread.finished.connect(lambda: self._auth_workers.remove(worker) if worker in self._auth_workers else None)
            thread.finished.connect(lambda: self.refresh_auth.setEnabled(True))
            self._auth_threads.append(thread)
            self._auth_workers.append(worker)
            thread.start()

        def _set_auth_status(self, status: object) -> None:
            principal = getattr(status, "principal", None)
            reason = getattr(status, "friendly_message", None) or getattr(status, "reason", None)
            self.principal.setText(f"{principal[0]}@{principal[1]}" if principal else (reason or "Unavailable"))

        def _open_logs(self) -> None:
            self.storage.log_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.storage.log_dir)))

        def _save(self) -> None:
            self.settings.assist_permission_mode = str(self.default_permission.currentData())
            self.settings.max_recent_computers = self.max_recents.value()
            self.settings.rdp_dynamic_resolution = self.dynamic.isChecked()
            self.settings.rdp_clipboard = self.clipboard.isChecked()
            self.settings.rdp_audio = self.audio.isChecked()
            self.settings.detailed_logging = self.detailed.isChecked()
            self.settings.ldap_server = self.ldap_server.text().strip()
            self.settings.ldap_search_base = self.ldap_base.text().strip()
            self.settings.recent = self.settings.recent[:self.settings.max_recent_computers]
            self.storage.save_settings(self.settings)
            self.accept()


    class DiagnosticsDialog(QDialog):
        sign_in_requested = Signal()

        def __init__(self, parent: QWidget | None = None) -> None:
            super().__init__(parent)
            self.setWindowTitle("Diagnostics")
            self.resize(620, 430)
            layout = QVBoxLayout(self)
            self.output = QTextEdit(readOnly=True)
            layout.addWidget(self.output)
            buttons = QDialogButtonBox(QDialogButtonBox.Close)
            self.run = buttons.addButton("Run Diagnostics", QDialogButtonBox.ActionRole)
            self.sign_in = buttons.addButton("Sign In", QDialogButtonBox.ActionRole)
            self.copy = buttons.addButton("Copy Results", QDialogButtonBox.ActionRole)
            buttons.rejected.connect(self.reject)
            self.copy.clicked.connect(lambda: QApplication.clipboard().setText(self.output.toPlainText()))
            self.sign_in.clicked.connect(lambda _checked=False: self.sign_in_requested.emit())
            layout.addWidget(buttons)

        def add_event(self, stage: object, message: str, detail: object) -> None:
            marker = {"ok": "✓", "wait": "…", "error": "✗", "info": "•"}.get(str(getattr(stage, "value", stage)), "•")
            self.output.append(f"{marker} {message}" + (f"\n    {detail}" if detail else ""))


    class DomainSignInDialog(QDialog):
        submitted = Signal()

        def __init__(self, kerberos: KerberosService, status: KerberosStatus, parent: QWidget | None = None) -> None:
            super().__init__(parent)
            self.setWindowTitle("Domain Sign In")
            self.setModal(True)
            self.setMinimumWidth(390)
            layout = QVBoxLayout(self)
            description = QLabel(f"Sign in to {status.realm or kerberos.default_realm} to access domain Windows computers.")
            description.setWordWrap(True)
            layout.addWidget(description)
            form = QFormLayout()
            self.username = QLineEdit(kerberos.default_username(status))
            self.password = QLineEdit()
            self.password.setEchoMode(QLineEdit.Password)
            self.realm = QLineEdit(status.realm or kerberos.default_realm)
            form.addRow("Username", self.username)
            form.addRow("Password", self.password)
            form.addRow("Realm", self.realm)
            layout.addLayout(form)
            self.error = QLabel()
            self.error.setWordWrap(True)
            self.error.setStyleSheet("color: palette(highlight);")
            self.error.hide()
            layout.addWidget(self.error)
            self.buttons = QDialogButtonBox(QDialogButtonBox.Cancel | QDialogButtonBox.Ok)
            self.sign_in = self.buttons.button(QDialogButtonBox.Ok)
            self.sign_in.setText("Sign In")
            self.buttons.accepted.connect(lambda: self.submitted.emit())
            self.buttons.rejected.connect(self.reject)
            layout.addWidget(self.buttons)

        def set_busy(self, busy: bool) -> None:
            for widget in (self.username, self.password, self.realm, self.sign_in):
                widget.setEnabled(not busy)
            self.buttons.button(QDialogButtonBox.Cancel).setEnabled(not busy)

        def show_error(self, message: str, detail: str | None = None) -> None:
            self.error.setText(message + (f"\n{detail}" if detail else ""))
            self.error.show()


    class MainWindow(QMainWindow):
        def __init__(self, *, start_authentication: bool = True) -> None:
            super().__init__()
            self.storage = Storage()
            self.settings = self.storage.load_settings()
            self.kerberos = KerberosService()
            self.controller = BackendController(kerberos_service=self.kerberos)
            self.controller.ldap_server = self.settings.ldap_server or None
            self.controller.ldap_search_base = self.settings.ldap_search_base or None
            self.result: CheckResult | None = None
            self._threads: list[QThread] = []
            self._workers: list[TaskWorker] = []
            self._worker_callbacks: list[WorkerCallbackProxy] = []
            self._processes: list[tuple[QProcess, Path | None]] = []
            self._directory_generation = 0
            self._check_generation = 0
            self._auth_status = KerberosStatus(KerberosStatusKind.MISSING, friendly_message="Sign-in required")
            self._auth_pending: list[tuple[Callable[[], None], Callable[[], None]]] = []
            self._auth_preflight_running = False
            self._auth_dialog: DomainSignInDialog | None = None
            self._auth_dialog_parent: QWidget | None = None
            self._auth_prompt_suppressed = False
            self.setWindowTitle("Remote Control")
            self.setMinimumSize(680, 510)
            self.resize(760, 570)
            self._build_ui()
            self._load_computers()
            self.statusBar().showMessage("Ready")
            # Let the first paint complete before reading the shared ticket cache.
            self._startup_auth_timer = QTimer(self)
            self._startup_auth_timer.setSingleShot(True)
            self._startup_auth_timer.timeout.connect(self.refresh_authentication)
            if start_authentication:
                self._startup_auth_timer.start(250)

        def _build_ui(self) -> None:
            central = QWidget()
            layout = QVBoxLayout(central)
            layout.setContentsMargins(24, 20, 24, 18)
            title_row = QHBoxLayout()
            title = QLabel("Remote Control")
            title.setStyleSheet("font-size: 24px; font-weight: 600;")
            subtitle = QLabel("Windows RDP and physical-console session assistance")
            subtitle.setStyleSheet("color: palette(mid);")
            title_column = QVBoxLayout()
            title_column.addWidget(title)
            title_column.addWidget(subtitle)
            self.settings_button = QToolButton()
            self.settings_button.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
            self.settings_button.setToolTip("Settings")
            self.settings_button.clicked.connect(self.show_settings)
            title_row.addLayout(title_column)
            title_row.addStretch()
            self.authentication_button = QToolButton()
            self.authentication_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
            self.authentication_button.setToolTip("Domain authentication status")
            self.authentication_button.clicked.connect(lambda _checked=False: self.request_domain_sign_in())
            title_row.addWidget(self.authentication_button)
            title_row.addWidget(self.settings_button)
            layout.addLayout(title_row)
            entry = QGridLayout()
            entry.addWidget(QLabel("Computer"), 0, 0)
            self.computer = QComboBox()
            self.computer.setEditable(True)
            self.computer.setInsertPolicy(QComboBox.NoInsert)
            self.computer.lineEdit().returnPressed.connect(self.check_computer)
            self.computer.lineEdit().textEdited.connect(self.schedule_directory_search)
            self.computer.setContextMenuPolicy(Qt.CustomContextMenu)
            self.computer.customContextMenuRequested.connect(self.show_context_menu)
            entry.addWidget(self.computer, 1, 0)
            self.check_button = QPushButton("Check")
            self.refresh_button = QPushButton("Refresh")
            self.check_button.clicked.connect(self.check_computer)
            self.refresh_button.clicked.connect(self.check_computer)
            entry.addWidget(self.check_button, 0, 1, 1, 1)
            entry.addWidget(self.refresh_button, 1, 1, 1, 1)
            self.directory_results = QListWidget()
            self.directory_results.setMaximumHeight(145)
            self.directory_results.setAlternatingRowColors(True)
            self.directory_results.hide()
            self.directory_results.itemActivated.connect(self.select_directory_result)
            entry.addWidget(self.directory_results, 2, 0, 1, 2)
            self.directory_timer = QTimer(self)
            self.directory_timer.setSingleShot(True)
            self.directory_timer.setInterval(350)
            self.directory_timer.timeout.connect(self.search_directory)
            layout.addLayout(entry)
            panel = QGroupBox("Active console session")
            panel_layout = QVBoxLayout(panel)
            self.user = QLabel("No computer checked")
            self.user.setStyleSheet("font-size: 19px; font-weight: 600;")
            self.session_detail = QLabel("")
            self.policy = QLabel("Remote Assistance: Policy will be checked with the computer.")
            self.policy.setWordWrap(True)
            self.message = QLabel("Enter a computer name, FQDN, or IP address, then select Check.")
            self.message.setWordWrap(True)
            panel_layout.addWidget(self.user)
            panel_layout.addWidget(self.session_detail)
            line = QFrame()
            line.setFrameShape(QFrame.HLine)
            panel_layout.addWidget(line)
            panel_layout.addWidget(self.policy)
            panel_layout.addWidget(self.message)
            layout.addWidget(panel, 1)
            actions = QHBoxLayout()
            self.assist = QPushButton("Assist User")
            self.rdp = QPushButton("Normal RDP")
            self.add_favorite = QPushButton("Add Favorite")
            self.remove_favorite = QPushButton("Remove Favorite")
            self.diagnostics = QPushButton("Diagnostics")
            for button in (self.assist, self.rdp, self.add_favorite, self.remove_favorite, self.diagnostics):
                actions.addWidget(button)
            actions.addStretch()
            self.assist.clicked.connect(self.open_assist)
            self.rdp.clicked.connect(self.launch_rdp)
            self.add_favorite.clicked.connect(lambda: self.change_favorite(True))
            self.remove_favorite.clicked.connect(lambda: self.change_favorite(False))
            self.diagnostics.clicked.connect(self.show_diagnostics)
            layout.addLayout(actions)
            self.setCentralWidget(central)
            self.assist.setEnabled(False)
            self.rdp.setEnabled(False)
            self.remove_favorite.setEnabled(False)
            menu = self.menuBar().addMenu("&File")
            quit_action = QAction("Quit", self)
            quit_action.triggered.connect(self.close)
            menu.addAction(quit_action)
            tools = self.menuBar().addMenu("&Tools")
            self.domain_sign_in_action = QAction("Domain Sign In", self)
            self.domain_sign_in_action.triggered.connect(lambda _checked=False: self.request_domain_sign_in())
            tools.addAction(self.domain_sign_in_action)
            refresh_auth_action = QAction("Refresh Authentication", self)
            refresh_auth_action.triggered.connect(self.refresh_authentication)
            tools.addAction(refresh_auth_action)
            diag_action = QAction("Diagnostics", self)
            diag_action.triggered.connect(self.show_diagnostics)
            tools.addAction(diag_action)
            setting_action = QAction("Settings", self)
            setting_action.triggered.connect(self.show_settings)
            tools.addAction(setting_action)

        def _load_computers(self) -> None:
            self.settings = self.storage.load_settings()
            current = self.computer.currentText()
            self.computer.clear()
            for item in dict.fromkeys([*self.settings.favorites, *self.settings.recent]):
                self.computer.addItem(item)
                friendly = self.settings.favorite_names.get(item, "")
                if friendly:
                    self.computer.setItemData(self.computer.count() - 1, friendly, Qt.ToolTipRole)
            self.computer.setCurrentText(current or self.settings.last_computer)

        def discover_directory(self) -> None:
            if not self._auth_status.available:
                self.statusBar().showMessage("Domain Authentication — sign-in required; manual computer entry remains available")
                return
            self._run_worker(lambda emit: self.controller.directory_status(emit), self._directory_status_complete)

        def _directory_status_complete(self, status: object) -> None:
            if getattr(status, "authenticated", False):
                self.statusBar().showMessage(f"Domain Authentication ✓ {getattr(status, 'realm', '')} via {getattr(status, 'server', '')}")
            else:
                self.statusBar().showMessage("Domain Authentication unavailable — manual computer entry remains available")

        def schedule_directory_search(self, text: str) -> None:
            self._directory_generation += 1
            if len(text.strip()) < 2:
                self.directory_timer.stop()
                self.directory_results.hide()
                return
            self.directory_timer.start()

        def search_directory(self) -> None:
            query = self._target()
            if len(query) < 2:
                return
            generation = self._directory_generation
            self._require_domain_authentication(
                lambda: self._search_directory_authenticated(query, generation),
                lambda: self.statusBar().showMessage("Domain authentication is required for Active Directory search"),
            )

        def _search_directory_authenticated(self, query: str, generation: int) -> None:
            for thread in getattr(self, "_directory_threads", []):
                thread.requestInterruption()
            thread = self._run_worker(
                lambda emit: self.controller.search_directory(query, emit),
                lambda value: self._directory_search_complete(generation, value),
            )
            if not hasattr(self, "_directory_threads"):
                self._directory_threads: list[QThread] = []
            self._directory_threads.append(thread)
            thread.finished.connect(lambda: self._directory_threads.remove(thread) if thread in self._directory_threads else None)

        def _directory_search_complete(self, generation: int, value: tuple[object, list[object]]) -> None:
            if generation != self._directory_generation:
                return  # A newer keystroke superseded this worker's result.
            _status, results = value
            self.directory_results.clear()
            for computer in results:
                text = computer.hostname
                if computer.description:
                    text += f"\n{computer.description}"
                elif computer.dns_hostname:
                    text += f"\n{computer.dns_hostname}"
                item = QListWidgetItem(text)
                item.setData(Qt.UserRole, computer)
                self.directory_results.addItem(item)
            self.directory_results.setVisible(bool(results))

        def select_directory_result(self, item: QListWidgetItem) -> None:
            computer = item.data(Qt.UserRole)
            hostname = getattr(computer, "dns_hostname", "") or getattr(computer, "hostname", "")
            if not hostname:
                return
            self.computer.setCurrentText(hostname)
            self.directory_results.hide()
            self._directory_generation += 1
            self.check_computer()

        def refresh_authentication(self) -> None:
            self._run_worker(lambda _emit: self.kerberos.get_status(), self._authentication_status_updated)

        def _authentication_status_updated(self, status: KerberosStatus) -> None:
            self._auth_status = status
            if status.available and status.principal:
                label = f"Domain Authentication\n✓ {status.principal[0]}@{status.principal[1]}"
                self.domain_sign_in_action.setText("Reauthenticate")
            elif status.kind is KerberosStatusKind.EXPIRED:
                label = "Domain Authentication\n⚠ Kerberos session expired"
                self.domain_sign_in_action.setText("Reauthenticate")
            else:
                label = "Domain Authentication\n⚠ Sign-in required"
                self.domain_sign_in_action.setText("Domain Sign In")
            self.authentication_button.setText(label)
            self.authentication_button.setToolTip(status.friendly_message or "Domain authentication status")
            if status.available:
                self.discover_directory()

        def request_domain_sign_in(self, parent: QWidget | None = None) -> None:
            if self._auth_dialog is not None:
                self._auth_dialog.raise_()
                self._auth_dialog.activateWindow()
                return
            self._auth_dialog_parent = parent or self
            self._auth_prompt_suppressed = False
            self._require_domain_authentication(lambda: self.statusBar().showMessage("Domain Authentication ✓ signed in"), lambda: None, force=True)

        def _require_domain_authentication(
            self, resume: Callable[[], None], cancelled: Callable[[], None], *, force: bool = False,
        ) -> None:
            if self.controller.auth_mode is not AuthenticationMode.KERBEROS:
                resume()
                return
            self._auth_pending.append((resume, cancelled))
            if self._auth_status.available:
                self._resume_authenticated_actions()
                return
            if self._auth_preflight_running or self._auth_dialog is not None:
                return
            if self._auth_prompt_suppressed and not force:
                self._cancel_authenticated_actions()
                return
            self._auth_preflight_running = True
            self._run_worker(lambda _emit: self.kerberos.get_status(), self._authentication_required_status, failed=self._authentication_worker_failed)

        def _authentication_required_status(self, status: KerberosStatus) -> None:
            self._auth_preflight_running = False
            self._authentication_status_updated(status)
            if status.available:
                self._resume_authenticated_actions()
                return
            if self._auth_prompt_suppressed:
                self._cancel_authenticated_actions()
                return
            self._auth_dialog = DomainSignInDialog(self.kerberos, status, self._auth_dialog_parent or self)
            self._auth_dialog.submitted.connect(self._submit_domain_sign_in)
            self._auth_dialog.rejected.connect(self._domain_sign_in_cancelled)
            self._auth_dialog.show()

        def _submit_domain_sign_in(self) -> None:
            dialog = self._auth_dialog
            if dialog is None:
                return
            username, realm, password = dialog.username.text(), dialog.realm.text(), dialog.password.text()
            dialog.password.clear()
            dialog.set_busy(True)
            self._run_worker(
                lambda _emit: self.kerberos.acquire_credentials(username, realm, password),
                self._domain_sign_in_finished,
                failed=self._authentication_worker_failed,
            )

        def _domain_sign_in_finished(self, result: KerberosAcquireResult) -> None:
            dialog = self._auth_dialog
            if result.success:
                if dialog is not None:
                    dialog.accept()
                self._auth_dialog = None
                self._auth_dialog_parent = None
                self._auth_prompt_suppressed = False
                self._authentication_status_updated(result.status)
                self._resume_authenticated_actions()
                return
            if dialog is not None:
                dialog.password.clear()
                dialog.set_busy(False)
                dialog.show_error(result.friendly_message, result.detail)
            self._authentication_status_updated(result.status)

        def _domain_sign_in_cancelled(self) -> None:
            if self._auth_dialog is not None:
                self._auth_dialog.password.clear()
            self._auth_dialog = None
            self._auth_dialog_parent = None
            self._auth_prompt_suppressed = True
            self.statusBar().showMessage("Domain sign-in cancelled")
            self._cancel_authenticated_actions()

        def _authentication_worker_failed(self, message: str, details: str) -> None:
            self._auth_preflight_running = False
            if self._auth_dialog is not None:
                self._auth_dialog.password.clear()
                self._auth_dialog.set_busy(False)
                self._auth_dialog.show_error("Domain authentication failed", "See application diagnostics for details.")
            self.storage.log(f"Authentication worker failure: {message}\n{details}", "DEBUG")
            self._cancel_authenticated_actions()

        def _resume_authenticated_actions(self) -> None:
            pending, self._auth_pending = self._auth_pending, []
            for resume, _cancelled in pending:
                resume()

        def _cancel_authenticated_actions(self) -> None:
            pending, self._auth_pending = self._auth_pending, []
            for _resume, cancelled in pending:
                cancelled()

        def _target(self) -> str:
            return self.computer.currentText().strip()

        def _run_worker(
            self, task: Callable[[Callable[..., None]], Any], completed: Callable[[Any], None],
            progress_target: Any | None = None, failed: Callable[[str, str], None] | None = None,
        ) -> QThread:
            thread = QThread(self)
            worker = TaskWorker(task)
            callback_proxy = WorkerCallbackProxy(completed, failed or self.show_error, progress_target, self.show_error, self)
            worker.moveToThread(thread)
            thread.started.connect(worker.run)
            worker.completed.connect(callback_proxy.handle_completed)
            worker.failed.connect(callback_proxy.handle_failed)
            worker.progress.connect(callback_proxy.handle_progress)
            worker.done.connect(thread.quit)
            worker.done.connect(worker.deleteLater)
            thread.finished.connect(thread.deleteLater)
            thread.finished.connect(lambda: self._threads.remove(thread) if thread in self._threads else None)
            thread.finished.connect(lambda: self._workers.remove(worker) if worker in self._workers else None)
            thread.finished.connect(lambda: self._worker_callbacks.remove(callback_proxy) if callback_proxy in self._worker_callbacks else None)
            self._threads.append(thread)
            self._workers.append(worker)
            self._worker_callbacks.append(callback_proxy)
            thread.start()
            return thread

        def check_computer(self) -> None:
            target = self._target()
            if not target:
                self.show_error("Enter a computer name, FQDN, or IP address.", "")
                return
            # A check always invalidates a previous selection; never assist a stale host.
            self.result = None
            self.assist.setEnabled(False)
            self.rdp.setEnabled(False)
            self._check_generation += 1
            generation = self._check_generation
            self.user.setText("Checking computer…")
            self.session_detail.setText(target)
            self.policy.setText("Remote Assistance: Checking Windows policy…")
            self.message.setText(f"Checking {target}…")
            self._set_busy(True, f"Checking {target}…")
            self.storage.log(f"Check started: {target}", "DEBUG")
            self._run_worker(
                lambda progress: self.controller.check(target, progress),
                lambda result: self._check_complete(generation, result),
                lambda stage, message, detail: self._check_progress(generation, target, stage, message, detail),
                lambda message, details: self._check_worker_failed(generation, target, message, details),
            )

        def _check_progress(self, generation: int, target: str, _stage: object, message: str, _detail: object) -> None:
            if generation == self._check_generation:
                self.statusBar().showMessage(f"Checking {target} — {message}")

        def _check_complete(self, generation: int, result: CheckResult) -> None:
            if generation != self._check_generation:
                return
            self._set_busy(False, "Computer check complete")
            self.result = result
            self._log_check_stages(result)
            if result.succeeded:
                self.storage.remember(result.target)
                self._load_computers()
            if not result.succeeded:
                if result.failure_stage == "Kerberos":
                    target = result.requested_target or result.target
                    self._set_busy(True, "Domain sign-in required")
                    self._require_domain_authentication(
                        lambda: self._retry_authenticated_check(target),
                        lambda: self._check_authentication_cancelled(generation, target),
                    )
                    return
                self._display_check_failure(result)
                return
            console = result.console
            capabilities = policy_capabilities(result.policy, console)
            self.policy.setText(f"Remote Assistance: {result.policy.friendly_name}")
            if console:
                self.user.setText(console.account_name)
                self.session_detail.setText(f"Console | Session ID {console.session_id} | {console.state}" + (f" | {result.address}" if result.address else ""))
                self.message.setText(capabilities.reason or "A console user is ready for session assistance.")
                self.statusBar().showMessage(f"● Online — active console user found: {console.account_name}")
            else:
                self.user.setText("No active console user")
                self.session_detail.setText(result.address or "")
                self.message.setText("No user is currently signed into the physical console. Normal RDP remains available.")
                self.statusBar().showMessage("● Online — no active console user")
            self.assist.setEnabled(capabilities.assist_enabled)
            self.rdp.setEnabled(result.freerdp is not None)
            is_favorite = result.target.lower() in {item.lower() for item in self.settings.favorites}
            self.add_favorite.setEnabled(not is_favorite)
            self.remove_favorite.setEnabled(is_favorite)

        def _retry_authenticated_check(self, target: str) -> None:
            self.computer.setCurrentText(target)
            self.check_computer()

        def _check_authentication_cancelled(self, generation: int, target: str) -> None:
            if generation != self._check_generation:
                return
            self._set_busy(False, "Domain sign-in cancelled")
            self.user.setText("Domain authentication required")
            self.session_detail.setText(target)
            self.policy.setText("Remote Assistance: Not checked because domain authentication was cancelled.")
            self.message.setText("Domain authentication is required to query this Windows computer.")
            self.assist.setEnabled(False)
            self.rdp.setEnabled(False)

        def _log_check_stages(self, result: CheckResult) -> None:
            for stage in result.stages:
                detail = f" — {stage.detail}" if stage.detail else ""
                self.storage.log(f"Check {result.target} [{stage.name}] {stage.status.value}: {stage.message}{detail}", "DEBUG")
            self.storage.log(
                f"Check {'completed' if result.succeeded else 'failed'}: {result.target}", "DEBUG"
            )

        def _display_check_failure(self, result: CheckResult) -> None:
            target = result.target or result.requested_target or "computer"
            stage = result.failure_stage or "computer check"
            message = result.failure_message or "Windows session information could not be retrieved"
            detail = result.failure_detail or "See Diagnostics or the debug log for details."
            self.user.setText("Unable to query computer")
            address = f" • {result.address}" if result.address else ""
            self.session_detail.setText(f"{target}{address}")
            self.policy.setText("Remote Assistance: Not checked because the machine query did not complete.")
            self.message.setText(f"{target} was checked through {stage}, but Windows session information could not be retrieved. {message}: {detail}")
            self.assist.setEnabled(False)
            self.rdp.setEnabled(False)
            self.statusBar().showMessage(f"● {message} — {stage}")
            trace = result.debug_trace or "No Python traceback was available."
            self.storage.log(f"Computer check failed at {stage} for {target}\n{trace}", "DEBUG")

        def _check_worker_failed(self, generation: int, target: str, message: str, details: str) -> None:
            if generation != self._check_generation:
                return
            self._set_busy(False, "Computer check failed")
            self.result = None
            self.user.setText("Unable to query computer")
            self.session_detail.setText(target)
            self.policy.setText("Remote Assistance: Not checked because the machine query failed.")
            self.message.setText(f"{target} could not be checked. {message}")
            self.assist.setEnabled(False)
            self.rdp.setEnabled(False)
            self.storage.log(f"Unexpected computer-check worker failure for {target}\n{details}", "DEBUG")
            self.show_error(message, details)

        def _set_busy(self, busy: bool, status: str) -> None:
            self.check_button.setEnabled(not busy)
            self.refresh_button.setEnabled(not busy)
            self.statusBar().showMessage(status)

        def open_assist(self) -> None:
            if self.result is None:
                return
            dialog = AssistDialog(self.result, self.settings, self)
            if dialog.exec() != QDialog.Accepted:
                return
            progress = ProgressDialog(f"Connecting to {self.result.target}", self)
            progress.show()
            self.storage.remember(self.result.target, dialog.permission.value)
            self.settings = self.storage.load_settings()
            session_id = self.result.console.session_id if self.result.console else None
            self._run_worker(
                lambda emit: self.controller.request_assistance(self.result.target, session_id, dialog.permission, dialog.interaction, emit),
                lambda value: self._assist_complete(value, progress), progress.add_event,
            )
            progress.finished.connect(lambda _: None)

        def _assist_complete(self, value: tuple[str, CheckResult, object], progress: ProgressDialog) -> None:
            invitation, result, _decision = value
            try:
                temporary_dir = Path(tempfile.mkdtemp(prefix="remote-control-"))
                invitation_file = write_private_invitation(invitation, temporary_dir / "shadow.msrcIncident")
                if result.freerdp is None:
                    raise AssistanceError("FreeRDP is not installed; assistance was not launched.")
                self._launch_process(invitation_command(invitation_file, result.freerdp), "Remote Assistance", invitation_file)
                progress.add_event("ok", "Starting FreeRDP with the existing-session invitation", None)
                progress.finish("Assistance accepted")
            except Exception as error:
                progress.finish("Assistance failed")
                self.show_error(str(error), traceback.format_exc())

        def launch_rdp(self) -> None:
            target = self.result.target if self.result else self._target()
            if not target:
                return
            self._set_busy(True, "Preparing normal RDP…")
            self._require_domain_authentication(
                lambda: self._launch_rdp_authenticated(target),
                lambda: self._set_busy(False, "Domain sign-in cancelled"),
            )

        def _launch_rdp_authenticated(self, target: str) -> None:
            def prepare(progress: Callable[..., None]):
                credentials, _ = self.controller.credentials(progress)
                from session_assist.services.rdp import detect_freerdp
                return credentials, detect_freerdp()
            self._run_worker(lambda emit: prepare(emit), lambda value: self._rdp_complete(target, value))

        def _rdp_complete(self, target: str, value: tuple[object, object]) -> None:
            self._set_busy(False, "")
            credentials, client = value
            command = normal_rdp_command(
                target, credentials, client, dynamic_resolution=self.settings.rdp_dynamic_resolution,
                clipboard=self.settings.rdp_clipboard, audio=self.settings.rdp_audio,
            )
            self._launch_process(command, "Normal RDP")

        def _launch_process(self, command: list[str], label: str, invitation: Path | None = None) -> None:
            process = QProcess(self)
            process.setProgram(command[0])
            process.setArguments(command[1:])
            process.setProcessChannelMode(QProcess.SeparateChannels)
            process.errorOccurred.connect(lambda _: self.show_error(f"{label} failed to start.", process.errorString()))
            process.started.connect(lambda: self.statusBar().showMessage(f"{label} started"))
            process.finished.connect(lambda _code, _status: self._process_finished(process, invitation, label))
            self._processes.append((process, invitation))
            process.start()

        def _process_finished(self, process: QProcess, invitation: Path | None, label: str) -> None:
            self.statusBar().showMessage(f"{label} exited")
            if invitation:
                shutil.rmtree(invitation.parent, ignore_errors=True)
            self._processes[:] = [entry for entry in self._processes if entry[0] is not process]
            process.deleteLater()

        def change_favorite(self, add: bool) -> None:
            target = self.result.target if self.result else self._target()
            if not target:
                return
            friendly = ""
            if add:
                friendly, accepted = QInputDialog.getText(self, "Add Favorite", "Display name (optional):")
                if not accepted:
                    return
            changed = self.storage.add_favorite(target, friendly) if add else self.storage.remove_favorite(target)
            self._load_computers()
            self.add_favorite.setEnabled(not add)
            self.remove_favorite.setEnabled(add)
            self.statusBar().showMessage(f"{target} {'added to' if add else 'removed from'} Favorites" if changed else "Favorites unchanged")

        def show_settings(self) -> None:
            if SettingsDialog(self.storage, self.controller, self.result, self).exec() == QDialog.Accepted:
                self._load_computers()
                self.controller.ldap_server = self.settings.ldap_server or None
                self.controller.ldap_search_base = self.settings.ldap_search_base or None
                self.discover_directory()

        def show_context_menu(self, position: object) -> None:
            target = self.result.target if self.result else self._target()
            if not target:
                return
            menu = QMenu(self)
            refresh = menu.addAction("Refresh")
            refresh.triggered.connect(self.check_computer)
            assist = menu.addAction("Assist User")
            assist.setEnabled(self.assist.isEnabled())
            assist.triggered.connect(self.open_assist)
            rdp = menu.addAction("Normal RDP")
            rdp.setEnabled(self.rdp.isEnabled())
            rdp.triggered.connect(self.launch_rdp)
            menu.addSeparator()
            favorite = menu.addAction("Remove Favorite" if self.remove_favorite.isEnabled() else "Add Favorite")
            favorite.triggered.connect(lambda: self.change_favorite(not self.remove_favorite.isEnabled()))
            menu.addSeparator()
            copy_host = menu.addAction("Copy Hostname")
            copy_host.triggered.connect(lambda: QApplication.clipboard().setText(target))
            copy_ip = menu.addAction("Copy IP")
            copy_ip.setEnabled(bool(self.result and self.result.address))
            copy_ip.triggered.connect(lambda: QApplication.clipboard().setText(self.result.address if self.result and self.result.address else ""))
            menu.exec(self.computer.mapToGlobal(position))

        def show_diagnostics(self) -> None:
            dialog = DiagnosticsDialog(self)
            target = self.result.target if self.result else self._target()
            def run() -> None:
                dialog.output.clear()
                status = self._auth_status
                if status.available and status.principal:
                    dialog.add_event("ok", "Kerberos authenticated", f"Principal: {status.principal[0]}@{status.principal[1]}\nCredential cache: available\nTicket: valid")
                    dialog.sign_in.hide()
                else:
                    dialog.add_event("error", "Kerberos authentication required", status.friendly_message or "Sign in to query domain computers.")
                    dialog.sign_in.show()
                    return
                if not target:
                    dialog.add_event("error", "Enter a computer before running diagnostics", None)
                    return
                def diagnose(emit: Callable[..., None]):
                    result = self.controller.check(target, emit)
                    self.controller.test_directory(emit)
                    return result
                self._run_worker(lambda emit: diagnose(emit), lambda value: dialog.add_event("ok", "Diagnostics complete", None), dialog.add_event)
            dialog.run.clicked.connect(run)
            dialog.sign_in_requested.connect(lambda: self.request_domain_sign_in(dialog))
            if target:
                run()
            dialog.exec()

        def show_error(self, message: str, details: str) -> None:
            self._set_busy(False, "Operation failed")
            if details:
                self.storage.log(f"Worker failure: {message}\n{details}", "DEBUG")
            box = QMessageBox(QMessageBox.Critical, "Remote Control", message, QMessageBox.Ok, self)
            if details:
                box.setDetailedText(details)
            box.exec()

        def closeEvent(self, event: object) -> None:
            """Prevent a deferred startup cache probe from beginning during shutdown."""
            self._startup_auth_timer.stop()
            super().closeEvent(event)


def main() -> int:
    if PYSIDE_ERROR is not None:
        print("Remote Control GUI requires PySide6. Install the project GUI dependency and retry.", file=sys.stderr)
        return 2
    QApplication.setApplicationName("Remote Control")
    QApplication.setApplicationDisplayName("Remote Control")
    QApplication.setOrganizationName("Remote Control")
    QApplication.setOrganizationDomain("local.remote-control")
    app = QApplication(sys.argv)
    app.setDesktopFileName("remote-control")
    icon = QIcon.fromTheme("remote-control")
    if icon.isNull():
        source_icon = Path(__file__).resolve().parents[3] / "data" / "icons" / "hicolor" / "scalable" / "apps" / "remote-control.svg"
        icon = QIcon(str(source_icon))
    app.setWindowIcon(icon)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
