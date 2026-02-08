import flet as ft

from ....logs.logger import client_logger
from ...controls.custom_controls import CustomTextField, CustomBtn
from ...utils.validation import AuthValidatior

# --Backend imports--
from ....core.authentication.auth_handler import RspStatus, FailReason

class SignUpView:
    def __init__(self, page: ft.Page):
        self.page = page
        
        # --- UI Controls ---
        self.user_input = CustomTextField(
            label_text="Set Username:", 
            field_width=300, 
            hint_text="username",
            icon_name=ft.Icons.ACCOUNT_CIRCLE_OUTLINED,
        )

        self.pass_input = CustomTextField(
            label_text="Set Password:",  
            field_width=300, 
            hint_text="password", 
            password=True,
            icon_name=ft.Icons.PASSWORD,
            can_reveal_password=True,
        )

        self.signup_btn = CustomBtn(
            text="Sign Up",
            on_click=self.handle_signup,
        )
        
        self.error_banner = ft.Text(value="", color=ft.Colors.ERROR, size=14, visible=False)

        # --- Layout ---
        controls_cont = ft.Container(
            content=ft.Column(
                controls=[
                    ft.Text(
                        value="SafeProxy Sign Up", 
                        color=ft.Colors.PRIMARY, 
                        weight=ft.FontWeight.BOLD, 
                        text_align=ft.TextAlign.CENTER, 
                        size=40
                    ),
                    self.user_input,
                    self.pass_input,
                    self.error_banner,
                    self.signup_btn,
                    
                    ft.TextButton(
                        text="Already have an account? Login",
                        style=ft.ButtonStyle(color=ft.Colors.PRIMARY), 
                        on_click=lambda _: self.page.go("/login")
                    )
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER, 
                alignment=ft.MainAxisAlignment.CENTER,             
                spacing=20,
            ),
            padding=40,
            border_radius=20,
            width=600,
            alignment=ft.alignment.center
        )

        self.content = ft.ResponsiveRow(
            controls=[controls_cont],
            height=self.page.height,
            alignment=ft.MainAxisAlignment.CENTER,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )

    def handle_signup(self, e):
        
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
        response = self.page.auth_handler.signup(username, password)

        if response.status == RspStatus.SUCCESS and response.jwt_token:
            client_logger.info(f"Signup Successful as {username}, Auto-Logging in...")
            self.page.session.set("username", username)
            self.page.session.set("jwt_token", response.jwt_token)
            self.page.go("/client_home")
        else:
            self._map_error_to_ui(response.fail_reason)
            self.page.update()

    def _map_error_to_ui(self, reason: FailReason):
        """
        Maps given backend errors to specific UI controls, 
        such as username textField or error
        banner for general error. 
        """
        if not reason or not isinstance(reason, FailReason):
            self.error_banner.value = "Unknown error occurred."
            self.error_banner.visible = True
            return
        
        # username
        if reason == FailReason.USER_EXISTS:
            self.user_input.error_text = reason.value
        
        # general
        else:
            self.error_banner.value = reason.value
            self.error_banner.visible = True

    def get_content(self):
        return self.content

def main(page: ft.Page):
    SignUpView(page)
    page.update()

if __name__ == "__main__":
    # logging.basicConfig(level=client_logger.DEBUG)
    ft.app(target=main)