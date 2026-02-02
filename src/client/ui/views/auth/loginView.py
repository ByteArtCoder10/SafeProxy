
import flet as ft
from ...controls.custom_controls import CustomTextField, CustomBtn
from ...utils.validation import AuthValidatior

# --Backend imports--
from ....core.authentication.auth_handler import RspStatus, FailReason

class LoginView:
    def __init__(self, page: ft.Page):
        self.page = page
        
        # --- Controls ---
        self.user_input = CustomTextField(
            label_text="Username:", 
            field_width=300, 
            hint_text="Enter username",
            icon_name=ft.Icons.ACCOUNT_CIRCLE_OUTLINED,
        )

        self.pass_input = CustomTextField(
            label_text="Password:",  
            field_width=300, 
            hint_text="Enter password", 
            password=True,
            icon_name=ft.Icons.PASSWORD,
            can_reveal_password=True,
        )
        
        self.login_btn = CustomBtn(
            text="Login",
            on_click=self.handle_login,
        )
        
        self.error_banner = ft.Text(value="", color=ft.Colors.ERROR, size=14, visible=False)

        # --- Layout ---
        controls_cont = ft.Container(
            content=ft.Column(
                controls=[
                    ft.Text(
                        value="SafeProxy Login", 
                        color=ft.Colors.PRIMARY, 
                        weight=ft.FontWeight.BOLD, 
                        text_align=ft.TextAlign.CENTER, 
                        size=40
                    ),
                    self.user_input,
                    self.pass_input,
                    self.error_banner,
                    self.login_btn,
                    
                    ft.TextButton(
                        text="Don't have an account? Sign Up",
                        style=ft.ButtonStyle(color=ft.Colors.PRIMARY),
                        on_click=lambda _: self.page.go("/signup")
                    )
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                alignment=ft.MainAxisAlignment.CENTER,             
                spacing=20,
            ),
            padding=40,
            border_radius=20,
            width=600,
            alignment=ft.alignment.center,
        )

        self.content = ft.ResponsiveRow(
            controls=[controls_cont],
            height=self.page.height,
            alignment=ft.MainAxisAlignment.CENTER,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )

    def handle_login(self, e):
        """
        Validates input locally, calls backend, and maps errors to fields.
        """
        # Reset error fields
        self.user_input.error_text = None
        self.pass_input.error_text = None
        self.error_banner.visible = False
        
        # length check
        username = self.user_input.value.strip()
        password = self.pass_input.value.strip()
        
        if not AuthValidatior._validate_fields_length(username, password, self.user_input, self.pass_input):
            self.page.update()
            return 

        # Check DB (backend requst to AuthServer)
        response = self.page.auth_handler.login(username, password)

        if response.status == RspStatus.SUCCESS:
            print("[UI] Login Successful")
            self.page.session.set("username", username)
            self.page.go("/client_home")

        else:
            self._map_error_to_ui(response.fail_reason)
            self.page.update()

    def _map_error_to_ui(self, reason: FailReason):
        """
        Maps given backend errors to specific UI controls, 
        such as username textField, pw textField or error
        banner for general error. 
        """
        if not reason or not isinstance(reason, FailReason):
            self.error_banner.value = "Unknown error occurred."
            self.error_banner.visible = True
            return

        # username
        if reason in [FailReason.USER_DOESNT_EXIST, FailReason.INVALID_USERNAME_LEN]:
            self.user_input.error_text = reason.value
        
        # pw
        elif reason in [FailReason.WRONG_PW, FailReason.INVALID_PW_LEN]:
            self.pass_input.error_text = reason.value
            
        # general error - for example ConnectionError
        else:
            self.error_banner.value = reason.value
            self.error_banner.visible = True

    def get_content(self) -> ft.ResponsiveRow:
        return self.content
    
def main(page: ft.Page):
    LoginView(page)
    page.update()

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.DEBUG)
    ft.app(target=main)