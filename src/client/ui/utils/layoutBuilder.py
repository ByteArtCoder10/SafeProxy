import flet as ft
from ..controls.custom_controls import SideBar

class LayoutBuilder:
    """
    This class defines the structure of the application.
    It manages the Sidebar and the Main Content Area, and decides
    based on view_type parameter, if the sidebar should appear in the view or not.
    """

    def __init__(self, page: ft.Page):
        self.page = page

    def build(self, content_control: ft.Control, view_type: str, title: str) -> ft.Row:
        """
        Wraps the specific view content with the app structure.
        view_type: 'public' (Login/Signup) or 'prviate' (Home/Dashboard/Logs/Certs...)
        """
        
        # if public, just return the content centered
        if view_type == "public":
            return ft.Container(
                content=content_control,
                alignment=ft.alignment.center,
                expand=True,
            )

        # If private, return Row[Sidebar, Content]
        sidebar = SideBar(route=title)
        
        return ft.Row(
            controls=[
                sidebar,
                # Main Content Area
                ft.Container(
                    content=content_control,
                    expand=True,
                    padding=30,
                    alignment=ft.alignment.top_left, 
                    bgcolor= ft.Colors.SURFACE,
                ),
            ],
            expand=True,
            spacing=0,
        )