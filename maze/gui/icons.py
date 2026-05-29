from pathlib import Path
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtCore import Qt

_LOGO_PATH = Path(__file__).parent.parent.parent / "MAZE.png"


def create_app_icon(size: int = 64) -> QIcon:
    if _LOGO_PATH.exists():
        pixmap = QPixmap(str(_LOGO_PATH))
        if not pixmap.isNull():
            return QIcon(pixmap.scaled(size, size, Qt.AspectRatioMode.KeepAspectRatio,
                                       Qt.TransformationMode.SmoothTransformation))

    # Fallback: plain text icon if PNG is missing
    from PyQt6.QtGui import QPainter, QColor, QFont
    pixmap = QPixmap(size, size)
    pixmap.fill(QColor("#0a0a0a"))
    p = QPainter(pixmap)
    p.setPen(QColor("#f0f0f0"))
    font = QFont("sans-serif", size // 5, QFont.Weight.Bold)
    p.setFont(font)
    p.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "M")
    p.end()
    return QIcon(pixmap)
