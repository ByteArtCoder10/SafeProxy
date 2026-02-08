import flet as ft
import logging

from src.client.ui.utils.viewRouter import ViewRouter
from ..logs.logging_manager import LoggingManager
from ..core.authentication.auth_handler import AuthHandler

def main(page: ft.Page):

    page.title = "SafeProxy Manager"
    page.padding = 0
    page.spacing = 0  

    page.theme = ft.Theme(
        # AI color scheme
        color_scheme=ft.ColorScheme(
            # Main Branding
            primary="#3c49f2",
            on_primary="#ffffff",
            primary_container="#e0e2fe", # Very light blue for active states/hover
            on_primary_container="#000d61",

            # Secondary (Used for less prominent actions/chips)
            secondary="#565fe4", 
            on_secondary="#ffffff",
            secondary_container="#dbe0ff",
            on_secondary_container="#001257",

            # Tertiary (Accents like 'Success' or 'Gold' highlights)
            tertiary="#006a6a", 
            on_tertiary="#ffffff",

            # Background & Surfaces (The Dribbble Look)
            surface="#F4F5F7",       # Page Background
            on_surface="#1a1c1e",    # Main Text
            surface_variant="#ffffff", # Card/Container Backgrounds
            on_surface_variant="#44474e", # Dimmed text / labels
            
            # Outlines & Borders
            outline="#dfdde9",       # Borders for TextFields and Cards
            outline_variant="#c4c6d0",

            # Error States
            error="#ba1a1a",
            on_error="#ffffff",

            # Surface Tint (The subtle blue overlay on top-level elements)
            surface_tint="#dfe1f7",
        ),
        visual_density=ft.VisualDensity.COMFORTABLE,
        )

    page.theme_mode = ft.ThemeMode.LIGHT

    
    # logging
    LoggingManager.setup_logging()
    
    # auth handler
    set_backend(page)
    

    router = ViewRouter(page)
    
    # Start login page
    page.go("/")

def set_backend(page : ft.Page):
    if not hasattr(page, "auth_handler"):
    # connect to auth-server
        page.auth_handler =  AuthHandler("127.0.0.1")
        page.auth_handler.connect()

    # if rsp status is SUCCESS and jwt provided, Start inject server
    # if response.status == RspStatus.SUCCESS and response.jwt_token:
    #     self._start_inject_server(response.jwt_token)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO) # flet logging system
    ft.app(target=main)
