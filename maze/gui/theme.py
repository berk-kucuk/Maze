_BASE = """
QWidget {{
    font-size: 13px;
    font-family: "Inter", "Segoe UI", "SF Pro Display", sans-serif;
}}

QTabWidget::pane {{
    border: none;
    border-top: 1px solid {border};
}}

QTabWidget > QWidget {{
    background-color: {bg};
}}

QTabBar {{
    background-color: {bg};
}}

QTabBar::tab {{
    background-color: {bg};
    color: {text_dim};
    padding: 10px 26px;
    border: none;
    border-bottom: 2px solid transparent;
    margin-right: 2px;
}}

QTabBar::tab:selected {{
    color: {text};
    border-bottom: 2px solid {text};
}}

QTabBar::tab:hover:!selected {{
    color: {text_mid};
}}

QTableWidget {{
    background-color: {bg};
    alternate-background-color: {surface};
    border: none;
    gridline-color: {border};
    color: {text};
    selection-background-color: {elevated};
    selection-color: {text};
    outline: none;
}}

QTableWidget::item {{
    padding: 5px 14px;
    border: none;
}}

QTableWidget::item:selected {{
    background-color: {elevated};
}}

QHeaderView {{
    background-color: {bg};
}}

QHeaderView::section {{
    background-color: {bg};
    color: {text_dim};
    padding: 8px 14px;
    border: none;
    border-bottom: 1px solid {border};
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 1px;
}}

QComboBox {{
    background-color: {surface};
    color: {text};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 5px 12px;
    min-width: 140px;
}}

QComboBox:hover {{
    border-color: {border2};
}}

QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: right center;
    width: 20px;
    border: none;
}}

QComboBox QAbstractItemView {{
    background-color: {surface};
    color: {text};
    border: 1px solid {border};
    selection-background-color: {elevated};
    selection-color: {text};
    outline: none;
    padding: 4px;
}}

QPushButton {{
    background-color: {surface};
    color: {text};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 5px 14px;
    min-width: 38px;
}}

QPushButton:hover {{
    background-color: {elevated};
    border-color: {border2};
}}

QPushButton:pressed {{
    background-color: {bg};
}}

QPushButton[active="true"] {{
    background-color: {accent};
    color: {accent_text};
    border-color: {accent};
}}

QPushButton[active="true"]:hover {{
    background-color: {accent_hover};
    border-color: {accent_hover};
}}

QScrollBar:vertical {{
    background: {bg};
    width: 5px;
    border: none;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background: {scrollbar};
    border-radius: 2px;
    min-height: 28px;
}}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {{
    height: 0;
    background: none;
}}

QScrollBar:horizontal {{
    background: {bg};
    height: 5px;
    border: none;
}}

QScrollBar::handle:horizontal {{
    background: {scrollbar};
    border-radius: 2px;
}}

QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal {{
    width: 0;
    background: none;
}}

QLabel {{
    background: transparent;
}}

QFrame[frameShape="4"],
QFrame[frameShape="5"] {{
    color: {border};
    background: {border};
}}

QMainWindow {{
    background-color: {bg};
}}

QWidget#header {{
    background-color: {bg};
    border-bottom: 1px solid {border};
}}

QLabel#logo {{
    color: {text};
    font-size: 17px;
    font-weight: bold;
    letter-spacing: 5px;
    background: transparent;
}}

QScrollArea {{
    background-color: {bg};
    border: none;
}}

QScrollArea > QWidget > QWidget {{
    background-color: {bg};
}}

QFrame#card {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 10px;
}}

QLabel#card_title {{
    color: {text_dim};
    font-size: 10px;
    font-weight: bold;
    letter-spacing: 2px;
    background: transparent;
}}

QLabel#card_value {{
    color: {text};
    font-size: 13px;
    background: transparent;
}}

QLabel#card_key {{
    color: {text_mid};
    font-size: 12px;
    background: transparent;
}}

QLabel#section_title {{
    color: {text_dim};
    font-size: 10px;
    font-weight: bold;
    letter-spacing: 2px;
    background: transparent;
}}

QPlainTextEdit {{
    background-color: {surface};
    color: {text};
    border: none;
    font-family: "Monospace", "Courier New", monospace;
    font-size: 11px;
    selection-background-color: {elevated};
}}

QPushButton#win_btn {{
    background: transparent;
    border: none;
    border-radius: 0;
    color: {text_mid};
    font-size: 15px;
    padding: 0;
    min-width: 44px;
    min-height: 44px;
}}

QPushButton#win_btn:hover {{
    background-color: {elevated};
    color: {text};
}}

QPushButton#win_close {{
    background: transparent;
    border: none;
    border-radius: 0;
    color: {text_mid};
    font-size: 15px;
    padding: 0;
    min-width: 44px;
    min-height: 44px;
}}

QPushButton#win_close:hover {{
    background-color: #c42b1c;
    color: #ffffff;
}}
"""

_DARK = {
    "bg":           "#0a0a0a",
    "surface":      "#111111",
    "elevated":     "#1a1a1a",
    "border":       "#1e1e1e",
    "border2":      "#2e2e2e",
    "text":         "#f0f0f0",
    "text_mid":     "#888888",
    "text_dim":     "#3a3a3a",
    "scrollbar":    "#2a2a2a",
    "accent":       "#f0f0f0",
    "accent_text":  "#0a0a0a",
    "accent_hover": "#cccccc",
}

_LIGHT = {
    "bg":           "#f5f5f5",
    "surface":      "#ffffff",
    "elevated":     "#ebebeb",
    "border":       "#e2e2e2",
    "border2":      "#cccccc",
    "text":         "#0a0a0a",
    "text_mid":     "#666666",
    "text_dim":     "#b0b0b0",
    "scrollbar":    "#c8c8c8",
    "accent":       "#0a0a0a",
    "accent_text":  "#f5f5f5",
    "accent_hover": "#282828",
}


def get_stylesheet(theme: str) -> str:
    palette = _DARK if theme == "dark" else _LIGHT
    return _BASE.format(**palette)


THREAT_COLORS = {
    "safe":       "#00e676",
    "suspicious": "#ffab00",
    "dangerous":  "#ff3d00",
}
