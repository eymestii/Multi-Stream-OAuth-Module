"""Capa 1 - Interfaz Qt6.

Ventana con dos botones: "Login con Twitch" y "Login con Kick". Al pulsar uno,
se inicia el flujo OAuth de la plataforma correspondiente y las credenciales se
guardan en el archivo de exposición.
"""

from __future__ import annotations

import sys
from typing import Optional

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..config import OAuthConfig, load_config
from ..credentials import CredentialsStore, OAuthCredentials
from ..manager import OAuthManager


class LoginWorker(QThread):
    """Ejecuta el flujo OAuth en un hilo secundario para no bloquear la UI."""

    finished = pyqtSignal(str, object)   # platform, credentials
    error = pyqtSignal(str, str)         # platform, message

    def __init__(self, manager: OAuthManager, platform: str) -> None:
        super().__init__()
        self.manager = manager
        self.platform = platform

    def run(self) -> None:  # noqa: D401
        try:
            credentials = self.manager.login(self.platform)
            self.finished.emit(self.platform, credentials)
        except Exception as exc:  # noqa: BLE001 - se reporta a la UI
            self.error.emit(self.platform, str(exc))


class MainWindow(QMainWindow):
    def __init__(
        self,
        config: Optional[OAuthConfig] = None,
        store: Optional[CredentialsStore] = None,
    ) -> None:
        super().__init__()
        self.config = config or load_config()
        self.store = store or CredentialsStore()
        self.manager = OAuthManager(self.config, self.store)

        self.setWindowTitle("OAuth Module - Twitch & Kick")
        self.resize(480, 320)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        title = QLabel("Módulo de Autenticación OAuth")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: bold; margin-bottom: 24px;")
        layout.addWidget(title)

        subtitle = QLabel(
            "Selecciona la plataforma con la que deseas iniciar sesión:"
        )
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)

        buttons = QHBoxLayout()
        self.btn_twitch = QPushButton("Login con Twitch")
        self.btn_kick = QPushButton("Login con Kick")
        for btn in (self.btn_twitch, self.btn_kick):
            btn.setMinimumSize(200, 50)
            buttons.addWidget(btn)
        layout.addLayout(buttons)

        self.status = QLabel("")
        self.status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status.setStyleSheet("color: #666; margin-top: 16px;")
        layout.addWidget(self.status)
        layout.addStretch()

        self.btn_twitch.clicked.connect(lambda: self._start_login("twitch"))
        self.btn_kick.clicked.connect(lambda: self._start_login("kick"))

        self._update_buttons_state()

    def _update_buttons_state(self) -> None:
        available = self.manager.available_platforms()
        self.btn_twitch.setEnabled("twitch" in available)
        self.btn_kick.setEnabled("kick" in available)
        if not available:
            self.status.setText(
                "No hay proveedores configurados. Revisa tu archivo .env"
            )

    def _start_login(self, platform: str) -> None:
        self.btn_twitch.setEnabled(False)
        self.btn_kick.setEnabled(False)
        self.status.setText(f"Esperando autorización de {platform}...")
        QApplication.processEvents()

        self.worker = LoginWorker(self.manager, platform)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self._on_error)
        self.worker.start()

    def _on_finished(self, platform: str, credentials: OAuthCredentials) -> None:
        self.status.setText(
            f"Sesión de {platform} autorizada. Credenciales guardadas en "
            f"{self.store.path}"
        )
        QMessageBox.information(
            self,
            "Autorización exitosa",
            f"Las credenciales de {platform} se han guardado correctamente.\n"
            f"Archivo: {self.store.path}",
        )
        self._update_buttons_state()

    def _on_error(self, platform: str, message: str) -> None:
        self.status.setText(f"Error en {platform}: {message}")
        QMessageBox.critical(
            self, f"Error de autorización - {platform}", message
        )
        self._update_buttons_state()


def run_gui(env_file: Optional[str] = None) -> int:
    config = load_config(env_file) if env_file else load_config()
    app = QApplication(sys.argv)
    window = MainWindow(config=config)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(run_gui())
