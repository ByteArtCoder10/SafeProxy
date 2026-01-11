import flet as ft
import sys
from  ....main import main as core_main

def main(page: ft.Page):
    page.title = "SafeProxy Admin Dashboard"
    page.theme_mode=ft.ThemeMode.DARK
    page.bgcolor = "black"
    page.window_width = 500
    page.window_height = 350
    primary_color = "#12ff00"
    header = ft.Row(
        [
            ft.Text("SafeProxy", size=30, weight="bold", color=ft.Colors.GREEN_600),
            ft.VerticalDivider(width=10, thickness=10, color=ft.Colors.WHITE),
            ft.Text("Admin Control Panel", size=25, color=ft.Colors.GREY_300),
        ],
        alignment=ft.MainAxisAlignment.START,
    )

    activate = ft.Row(
        [
            ft.Text("Activate Proxy", size=20, weight=ft.FontWeight.BOLD, color=primary_color),
            ft.Button("Activate", color=primary_color, on_click=start_proxy),
        ],
        alignment=ft.MainAxisAlignment.CENTER
    )

    def start_proxy():
        core_main()
    
    page.add(
        header,
        activate
    )

ft.app(target=main)