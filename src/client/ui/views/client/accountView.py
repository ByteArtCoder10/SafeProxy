import flet as ft
from ...controls.custom_controls import CustomTextField, CustomBtn, CustomCard, CardTitle, CustomPageHeader, CustomAlertDialog
from ....logs.logger import client_logger
class AccountView:
    def __init__(self, page: ft.Page):
        self.page = page


        self.delete_dialog = CustomAlertDialog("Delete Account", "Are you sure? This cannot be undone.", "Delete", "Cancel", on_click_yes=self._delete_account, on_click_no=self._close_dialog)
        self.page.overlay.append(self.delete_dialog)

        # controls
        header = CustomPageHeader("Account")
        delete_section = ft.Row(
            controls = 
            [
                ft.Text(value="Danger Zone:", weight="bold", size=18, color=ft.Colors.RED),
                ft.VerticalDivider(color=ft.Colors.with_opacity(0.4, ft.Colors.RED)),
                CustomBtn(text="Delete Account", bg_color=ft.Colors.RED, width=200, height=40, text_color=ft.Colors.WHITE, elevation=2, on_click=self._open_dialog)

            ],
            spacing=5       
        )
        
        self.content = ft.ResponsiveRow(
            controls= [header, delete_section],
            height=self.page.height,
            alignment=ft.MainAxisAlignment.CENTER,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            expand=True    
        )

    # Method to open the dialog
    def _open_dialog(self, e):
        self.delete_dialog.open = True
        self.page.update()

    # Method to close the dialog
    def _close_dialog(self, e):
        self.delete_dialog.open = False
        self.page.update()

    def _delete_account(self, e):
        client_logger.info("Account deleted")
        self._close_dialog(e)
    
    def get_content(self):
        return self.content