import os

import pytest


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtCore import QEvent, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialogButtonBox, QLineEdit

from session_assist.gui.app import DiagnosticsDialog, DomainSignInDialog, MainWindow
from session_assist.gui.controller import CheckResult
from session_assist.models import AuthenticationMode, ShadowPolicy, ShadowPolicyStatus
from session_assist.services.authentication import KerberosAcquireResult, KerberosService, KerberosStatus, KerberosStatusKind


def test_main_window_has_native_machine_first_controls():
    app = QApplication.instance() or QApplication([])
    window = MainWindow(start_authentication=False)
    try:
        assert window.windowTitle() == "Remote Control"
        assert window.computer.isEditable()
        assert window.assist.isEnabled() is False
        assert window.rdp.isEnabled() is False
    finally:
        window.close()
        app.processEvents()


def test_diagnostics_dialog_does_not_override_qdialog_event():
    app = QApplication.instance() or QApplication([])
    dialog = DiagnosticsDialog()
    try:
        dialog.setWindowTitle("Diagnostics regression")
        dialog.add_event("ok", "Hostname resolved", "teacher-pc.example.org → 192.0.2.12")
        assert "Hostname resolved" in dialog.output.toPlainText()
        assert isinstance(dialog.event(QEvent(QEvent.WindowActivate)), bool)
    finally:
        dialog.close()
        app.processEvents()


def failed_result(target="teacher-pc", stage="TerminalServices"):
    return CheckResult(
        target, "192.0.2.12", True, True, None, (), ShadowPolicy(ShadowPolicyStatus.UNKNOWN), None,
        failure_stage=stage, failure_message="Kerberos credentials are unavailable",
        failure_detail="Run kinit or use domain login first.", debug_trace="Traceback (most recent call last):\nexample",
    )


def test_machine_check_failure_updates_panel_and_resets_controls(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = QApplication.instance() or QApplication([])
    window = MainWindow(start_authentication=False)
    try:
        window._check_generation = 1
        window._set_busy(True, "Checking")
        window._check_complete(1, failed_result())
        assert window.check_button.isEnabled()
        assert window.refresh_button.isEnabled()
        assert window.user.text() == "Unable to query computer"
        assert "Kerberos credentials are unavailable" in window.message.text()
        assert window.assist.isEnabled() is False
    finally:
        window.close()
        app.processEvents()


def test_stale_check_completion_cannot_replace_newer_result(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = QApplication.instance() or QApplication([])
    window = MainWindow(start_authentication=False)
    try:
        window._check_generation = 2
        window.user.setText("Checking newest computer…")
        window._check_complete(1, failed_result("OLD-HOST"))
        assert window.user.text() == "Checking newest computer…"
        assert window.result is None
    finally:
        window.close()
        app.processEvents()


def test_unexpected_check_worker_failure_resets_controls(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = QApplication.instance() or QApplication([])
    window = MainWindow(start_authentication=False)
    try:
        monkeypatch.setattr(window, "show_error", lambda *_args: None)
        window._check_generation = 1
        window._set_busy(True, "Checking")
        window._check_worker_failed(1, "teacher-pc", "Unexpected backend failure", "Traceback")
        assert window.check_button.isEnabled()
        assert window.refresh_button.isEnabled()
        assert window.user.text() == "Unable to query computer"
    finally:
        window.close()
        app.processEvents()


def test_domain_sign_in_defaults_and_masks_password():
    app = QApplication.instance() or QApplication([])
    status = KerberosStatus(KerberosStatusKind.MISSING, friendly_message="Sign-in required")
    dialog = DomainSignInDialog(KerberosService(default_realm="EXAMPLE.ORG"), status)
    try:
        assert dialog.realm.text() == "EXAMPLE.ORG"
        assert dialog.username.text()
        assert dialog.password.echoMode() is QLineEdit.Password
        assert not dialog.password.text()
    finally:
        dialog.close()
        app.processEvents()


def test_authenticated_operation_resumes_once_after_sign_in(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = QApplication.instance() or QApplication([])
    window = MainWindow(start_authentication=False)
    resumed = []
    try:
        monkeypatch.setattr(window, "discover_directory", lambda: None)
        window._auth_pending.append((lambda: resumed.append("check"), lambda: resumed.append("cancelled")))
        status = KerberosStatus(KerberosStatusKind.AVAILABLE, ("testuser", "EXAMPLE.ORG"), friendly_message="Authenticated")
        window._domain_sign_in_finished(KerberosAcquireResult(True, status, "Authenticated"))
        assert resumed == ["check"]
        assert window.authentication_button.text().endswith("testuser@EXAMPLE.ORG")
    finally:
        window.close()
        app.processEvents()


def test_cancelled_authentication_returns_check_to_idle(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = QApplication.instance() or QApplication([])
    window = MainWindow(start_authentication=False)
    try:
        window._check_generation = 1
        window._set_busy(True, "Checking")
        window._check_authentication_cancelled(1, "teacher-pc")
        assert window.check_button.isEnabled()
        assert window.refresh_button.isEnabled()
        assert window.user.text() == "Domain authentication required"
    finally:
        window.close()
        app.processEvents()


def test_suppressed_auth_prompt_does_not_repeat_for_debounced_search(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = QApplication.instance() or QApplication([])
    window = MainWindow(start_authentication=False)
    cancelled = []
    try:
        window._auth_prompt_suppressed = True
        window._auth_status = KerberosStatus(KerberosStatusKind.MISSING, friendly_message="Sign-in required")
        window._require_domain_authentication(lambda: None, lambda: cancelled.append("one"))
        window._require_domain_authentication(lambda: None, lambda: cancelled.append("two"))
        assert cancelled == ["one", "two"]
        assert window._auth_dialog is None
    finally:
        window.close()
        app.processEvents()


class FakeKerberosService:
    default_realm = "EXAMPLE.ORG"

    def __init__(self, *, success=True):
        self.status = KerberosStatus(KerberosStatusKind.MISSING, friendly_message="Sign-in required")
        self.success = success
        self.acquire_calls = []

    def get_status(self):
        return self.status

    def default_username(self, _status=None):
        return "testuser"

    def acquire_credentials(self, username, realm, password):
        self.acquire_calls.append((username, realm, password))
        if not self.success:
            status = KerberosStatus(KerberosStatusKind.ERROR, friendly_message="Sign-in failed", detail="The username or password was not accepted by the domain.")
            return KerberosAcquireResult(False, status, status.friendly_message, status.detail)
        self.status = KerberosStatus(KerberosStatusKind.AVAILABLE, (username, realm.upper()), friendly_message="Authenticated")
        return KerberosAcquireResult(True, self.status, "Authenticated")


def wait_for(app, condition, timeout=1000):
    elapsed = 0
    while elapsed < timeout:
        app.processEvents()
        if condition():
            return True
        QTest.qWait(20)
        elapsed += 20
    return condition()


def configured_auth_window(monkeypatch, tmp_path, *, success=True):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    window = MainWindow(start_authentication=False)
    service = FakeKerberosService(success=success)
    window.kerberos = service
    window.controller.kerberos_service = service
    window.show()
    return window, service


def test_qtest_main_authentication_button_opens_domain_sign_in(monkeypatch, tmp_path):
    app = QApplication.instance() or QApplication([])
    window, _service = configured_auth_window(monkeypatch, tmp_path)
    try:
        QTest.mouseClick(window.authentication_button, Qt.LeftButton)
        assert wait_for(app, lambda: window._auth_dialog is not None and window._auth_dialog.isVisible())
        assert window._auth_dialog is not None
        assert window._auth_dialog.thread() is window.thread()
    finally:
        if window._auth_dialog:
            window._auth_dialog.reject()
        window.close()
        QTest.qWait(40)


def test_tools_domain_sign_in_action_uses_the_shared_flow(monkeypatch, tmp_path):
    app = QApplication.instance() or QApplication([])
    window, _service = configured_auth_window(monkeypatch, tmp_path)
    try:
        window.domain_sign_in_action.trigger()
        assert wait_for(app, lambda: window._auth_dialog is not None and window._auth_dialog.isVisible())
    finally:
        if window._auth_dialog:
            window._auth_dialog.reject()
        window.close()
        QTest.qWait(40)


def test_qtest_diagnostics_sign_in_button_invokes_shared_flow(monkeypatch, tmp_path):
    app = QApplication.instance() or QApplication([])
    window, _service = configured_auth_window(monkeypatch, tmp_path)
    dialog = DiagnosticsDialog()
    dialog.sign_in_requested.connect(lambda: window.request_domain_sign_in(dialog))
    try:
        dialog.show()
        QTest.mouseClick(dialog.sign_in, Qt.LeftButton)
        assert wait_for(app, lambda: window._auth_dialog is not None and window._auth_dialog.isVisible())
        assert window._auth_dialog is not None
        assert window._auth_dialog.parent() is dialog
    finally:
        if window._auth_dialog:
            window._auth_dialog.reject()
        dialog.close()
        window.close()
        app.processEvents()


def test_qtest_domain_dialog_submit_runs_kinit_once(monkeypatch, tmp_path):
    app = QApplication.instance() or QApplication([])
    window, service = configured_auth_window(monkeypatch, tmp_path)
    monkeypatch.setattr(window, "discover_directory", lambda: None)
    try:
        QTest.mouseClick(window.authentication_button, Qt.LeftButton)
        assert wait_for(app, lambda: window._auth_dialog is not None)
        dialog = window._auth_dialog
        assert dialog is not None
        dialog.username.setText("admin")
        dialog.realm.setText("EXAMPLE.ORG")
        QTest.keyClicks(dialog.password, "not-in-arguments")
        QTest.mouseClick(dialog.sign_in, Qt.LeftButton)
        assert wait_for(app, lambda: len(service.acquire_calls) == 1 and window._auth_dialog is None)
        assert service.acquire_calls == [("admin", "EXAMPLE.ORG", "not-in-arguments")]
    finally:
        window.close()
        QTest.qWait(40)


def test_qtest_cancel_does_not_start_kinit(monkeypatch, tmp_path):
    app = QApplication.instance() or QApplication([])
    window, service = configured_auth_window(monkeypatch, tmp_path)
    try:
        QTest.mouseClick(window.authentication_button, Qt.LeftButton)
        assert wait_for(app, lambda: window._auth_dialog is not None)
        dialog = window._auth_dialog
        assert dialog is not None
        QTest.mouseClick(dialog.buttons.button(QDialogButtonBox.Cancel), Qt.LeftButton)
        assert wait_for(app, lambda: window._auth_dialog is None)
        assert service.acquire_calls == []
    finally:
        window.close()
        QTest.qWait(40)


def test_qtest_failed_sign_in_keeps_dialog_usable(monkeypatch, tmp_path):
    app = QApplication.instance() or QApplication([])
    window, service = configured_auth_window(monkeypatch, tmp_path, success=False)
    try:
        QTest.mouseClick(window.authentication_button, Qt.LeftButton)
        assert wait_for(app, lambda: window._auth_dialog is not None)
        dialog = window._auth_dialog
        assert dialog is not None
        QTest.keyClicks(dialog.password, "incorrect")
        QTest.mouseClick(dialog.sign_in, Qt.LeftButton)
        assert wait_for(app, lambda: len(service.acquire_calls) == 1 and dialog.error.isVisible())
        assert dialog.sign_in.isEnabled()
        assert "Sign-in failed" in dialog.error.text()
    finally:
        if window._auth_dialog:
            window._auth_dialog.reject()
        window.close()
        QTest.qWait(40)


def test_qtest_duplicate_requests_share_one_dialog(monkeypatch, tmp_path):
    app = QApplication.instance() or QApplication([])
    window, _service = configured_auth_window(monkeypatch, tmp_path)
    try:
        QTest.mouseClick(window.authentication_button, Qt.LeftButton)
        assert wait_for(app, lambda: window._auth_dialog is not None)
        first = window._auth_dialog
        window.domain_sign_in_action.trigger()
        QTest.qWait(80)
        assert window._auth_dialog is first
    finally:
        if window._auth_dialog:
            window._auth_dialog.reject()
        window.close()
        QTest.qWait(40)


def test_qtest_active_directory_search_requests_one_sign_in(monkeypatch, tmp_path):
    app = QApplication.instance() or QApplication([])
    window, _service = configured_auth_window(monkeypatch, tmp_path)
    try:
        QTest.keyClicks(window.computer.lineEdit(), "DC")
        assert wait_for(app, lambda: window._auth_dialog is not None and window._auth_dialog.isVisible(), timeout=1200)
        first = window._auth_dialog
        QTest.keyClicks(window.computer.lineEdit(), "-ES")
        QTest.qWait(420)
        assert window._auth_dialog is first
    finally:
        if window._auth_dialog:
            window._auth_dialog.reject()
        window.close()
        QTest.qWait(40)


def test_qtest_check_prompts_and_retries_after_successful_sign_in(monkeypatch, tmp_path):
    class CheckController:
        auth_mode = AuthenticationMode.KERBEROS

        def __init__(self, kerberos_service):
            self.kerberos_service = kerberos_service
            self.check_calls = 0

        def check(self, target, _progress):
            self.check_calls += 1
            if self.check_calls == 1:
                return CheckResult(
                    target, "192.0.2.12", True, True, None, (), ShadowPolicy(ShadowPolicyStatus.UNKNOWN), None,
                    requested_target=target, failure_stage="Kerberos", failure_message="Kerberos credentials are unavailable",
                )
            return CheckResult(target, "192.0.2.12", True, True, ("admin", "EXAMPLE.ORG"), (), ShadowPolicy(ShadowPolicyStatus.UNKNOWN), None)

    app = QApplication.instance() or QApplication([])
    window, service = configured_auth_window(monkeypatch, tmp_path)
    controller = CheckController(service)
    window.controller = controller
    monkeypatch.setattr(window, "discover_directory", lambda: None)
    try:
        window.computer.setCurrentText("teacher-pc.example.org")
        QTest.mouseClick(window.check_button, Qt.LeftButton)
        assert wait_for(app, lambda: window._auth_dialog is not None)
        dialog = window._auth_dialog
        assert dialog is not None
        QTest.keyClicks(dialog.password, "approved-password")
        QTest.mouseClick(dialog.sign_in, Qt.LeftButton)
        assert wait_for(app, lambda: controller.check_calls == 2 and window.check_button.isEnabled())
        assert window.user.text() == "No active console user"
    finally:
        if window._auth_dialog:
            window._auth_dialog.reject()
        window.close()
        QTest.qWait(40)
