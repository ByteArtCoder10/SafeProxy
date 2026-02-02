from enum import Enum
import flet as ft

class ColorPalatte(str, Enum):
    """
    Inherits form str too, so that flet color systme will accept directly
    ColorPalette.PRIMARY (because it expcets a string) isntead of doing
    ColorPalette.PRIMARY.value
    """
    PRIMARY = "#3c49f2"
    PRIMARY_LIGHT = "#565fe4"
    PRIMARY_DARK = "#0818fc"
    LIGHT = "#bec5fc"
    SEMI = "#a0abfd"
    SIDEBAR = "#f5f6ff"
    DARK = "#2c33ac"
    BG = "#ffffff"
    CARD_BORDER = "#efedf7",
    TEXT_FIELD_BORDER = "#dfdde9"