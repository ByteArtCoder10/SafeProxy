import flet as ft
from ...controls.custom_controls import CustomTextField, CustomBtn, CustomCard, CardTitle, CustomPageHeader
from ....core.ca_check.CA_handler import CAHandler
import threading

class CAView:
    def __init__(self, page: ft.Page):
        self.page = page
        header=  CustomPageHeader("Certificate Authority Installation")
        # btn install
        self.status_text = ft.Text("CHECKING...", color=ft.Colors.GREY, weight="bold")
        self.loading_ring = ft.ProgressRing(width=16, height=16, stroke_width=2)
        
        self.status_container = ft.Row(
            controls=[
                ft.Text("Installation Status:"),
                self.status_text,
                self.loading_ring
            ],
            alignment=ft.MainAxisAlignment.CENTER,
        )

        self.error_banner = ft.Text(value="Failed installing Certifcate", color=ft.Colors.ERROR, size=14, visible=False)

        self.install_btn = CustomBtn(text="Install SafeProxy CA", bg_color=ft.Colors.GREY, disabled=True, elevation=2, on_click=self._install_ca)

        
        staus_and_btn = ft.Column(
            controls=[self.status_container, self.install_btn],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
        # content
        text ='''
        A Certificate Authority (CA) is a digital organization that verifies the identity of websites to ensure your connection
        is secure. Your computer uses these authorities to confirm that the data you send and receive is encrypted and hasn't been
        tampered with by hackers. 
        
        SafeProxy needs its own certificate installed to provide active protection. Because most web traffic
        is encrypted, the proxy cannot see or block dangerous content without permission. By installing the certificate, you grant SafeProxy
        the ability to safely open, inspect, and re-secure your traffic to filter out threats and enforce your blacklist (TLS termination).
        Without this certificate, your browser will view the proxy as an intruder, resulting in security warnings and blocked internet access.
        '''
        
        para = CustomCard(ft.Text(text, color=ft.Colors.GREY_700, text_align=ft.TextAlign.START, size=15))

        self.content = ft.ResponsiveRow(
            controls=[header, staus_and_btn, para],
            height=self.page.height,
            alignment=ft.MainAxisAlignment.CENTER,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )

        if self.page.session.contains_key("CA_installed"):
            self._change_ui_installed() if self.page.session.get("CA_installed") else self._change_ui_not_installed()


        
    def _change_ui_installed(self):
        
        # ststus + loading
        self.status_text.value = "INSTALLED"
        self.status_text.color = ft.Colors.GREEN
        self.loading_ring.visible = False
        
        # btn
        self.install_btn.bgcolor = ft.Colors.GREY
        self.install_btn.disabled = True

        # error banner
        self.error_banner.visible = False

        self.page.update()

    def _change_ui_not_installed(self):
        # status + loaidng
        self.status_text.value = "NOT INSTALLED"
        self.status_text.color = ft.Colors.RED
        self.loading_ring.visible = False
        
        # btn
        self.install_btn.bgcolor = ft.Colors.PRIMARY
        self.install_btn.disabled = False

        # error banner
        self.error_banner.visible = False

        self.page.update()

    def _install_ca(self, e: ft.ControlEvent):
        if CAHandler.install_ca_cert():
            self.page.session.set("CA_installed", True)
            self._change_ui_installed()
        else:
            self.error_banner.visible = True
            self.page.update()
    
    def get_content(self) -> ft.ResponsiveRow:
        return self.content
        