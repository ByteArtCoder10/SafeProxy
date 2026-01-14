import flet as ft
import sys
import os
import threading
from src.ui.utils.colors import ColorPalatte
# Add the project root to sys.path so we can find 'main.py'
root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if root_path not in sys.path:
    sys.path.append(root_path)

import main as core_main 
def main(page: ft.Page):
    page.title = "SafeProxy Admin Dashboard"
    page.theme_mode = ft.ThemeMode.LIGHT
    page.bgcolor = ColorPalatte.BG
    page.window_width = 500
    page.window_height = 350

    def handle_activate_click(e):
        # Disable button to prevent double-click
        btn_activate.disabled = True
        page.update()
        
        # Start proxy in background thread
        proxy_thread = threading.Thread(target=core_main.main, daemon=True)
        proxy_thread.start()
        
        print("Proxy started in background thread.")

    header = ft.Container(
            content=ft.Row(
                height=60,
                controls=[
                    ft.Text(
                        "SafeProxy", 
                        size=30, 
                        weight="bold", 
                        color=ColorPalatte.PRIMARY
                    ),
                    
                    ft.VerticalDivider(
                        width=20,
                        thickness=2,   
                        color=ColorPalatte.PRIMARY,
                        leading_indent=21,
                        trailing_indent=13
                    ),
                    
                    ft.Text(
                        "Admin Dashboard", 
                        size=30, 
                        weight="bold",
                        color=ColorPalatte.PRIMARY
                    ),
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            padding=ft.padding.all(5),
        )


    settings = ft.Card(
        ft.Text(value="Settings"),
        bgcolor=ColorPalatte.BG,
        col=12

    )
    btn_activate = ft.Button("Activate", color=ColorPalatte.PRIMARY)

    page.add(
        header,
        settings,
        ft.Row([ft.Text("Activate Proxy", size=20), btn_activate], alignment=ft.MainAxisAlignment.CENTER)
    )

if __name__ == "__main__":
    ft.run(main=main)