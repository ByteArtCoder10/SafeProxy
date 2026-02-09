import flet as ft
from ...controls.custom_controls import CustomTextField, CustomBtn, CustomCard, CardTitle, CustomPageHeader
from ....core.inject_server.inject_server import InjectServer
class ClientHomeView:
    def __init__(self, page: ft.Page):
        self.page = page
        self.username = self.page.session.get("username") or "Client"
        self.page.inject_server = InjectServer(self.page.session.get("jwt_token"))

        # controls
        header = ft.Container(
            content=ft.Column([
                ft.Text(f"Welcome, {self.username}", size=32, weight="bold", color=ft.Colors.PRIMARY),
                ft.Text("Configure, manage, and modify your SafeProxy settings and connections.", size=16, color=ft.Colors.PRIMARY),
            ], spacing=5),
            margin=ft.margin.only(bottom=20),
            col={"xs": 12} # always takes full width - even when the window is small
        )

        cards = self.build_home_cards()

        self.content = ft.ResponsiveRow(
            controls=[header] + cards,
            height=self.page.height,
            alignment=ft.MainAxisAlignment.CENTER,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )
        
    def get_content(self) -> ft.ResponsiveRow:
        return self.content
    
    def build_home_cards(self):
        """Builds and returns the list of dashboard cards."""
        
        # Connection Card
        self.status_text = ft.Text("DISCONNECTED", color=ft.Colors.GREY, weight="bold")
        self.toggle_btn = ft.Switch(
            label="Activate Proxy    ",
            active_color=ft.Colors.PRIMARY,
            label_position=ft.LabelPosition.LEFT,
            on_change=self.handle_toggle_proxy,
            value=self.page.session.get("is_connected") or False
        )
        self.loading_ring = ft.ProgressRing(width=16, height=16, stroke_width=2, visible=False)
        self.set_status(self.page.session.get("is_connected"))
        conn_controls = ft.Column(
            controls=[
                CardTitle("Connection Status"),
                ft.Column(
                    controls=[
                        ft.Row(controls=[ft.Text("Status:", weight="bold"), self.status_text, self.loading_ring]),
                        self.toggle_btn,
                ], 
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN
                ),
            ],
            spacing=15
        )
        # Protocol Card
        protocol_controls = ft.Column(
            controls=[
                CardTitle("Tunneling Protocol"),
                ft.RadioGroup(
                    content=ft.Column([
                        ft.Radio(value="TCP", label="TCP Tunnel (Raw)"),
                        ft.Radio(value="TLS", label="TLS Termination (Secure)"),
                    ], spacing=10)
                ),
                # maybe later add info about choosing and Warningmsgbox 
                ft.Text("TLS allows data inspection for enhanced security.", size=12, color=ft.Colors.GREY_500)
            ], 
            spacing=15
        )

        # Redirection Card
        redirect_controls = ft.Column(
            controls=[
                CardTitle("Redirection Strategy"),
                ft.RadioGroup(
                    content=ft.Column([
                        ft.Radio(value="redirect", label="Smart Redirect (To Google Search)"),
                        ft.Radio(value="504_rsp", label="Send a 504 'Bad Request' response"),
                    ])
                ),
                ft.Text("Handles invalid host requests automatically.", size=12, color=ft.Colors.GREY_500)
            ], 
            spacing=15
        )

        # Blacklist Card
        blacklist_controls = ft.Column(
            controls=[
                CardTitle("Blacklisted Hosts/IPs"),
                ft.Text("The blacklsit feature allows you to block any site you wish!", color=ft.Colors.GREY_500),
                ft.DataTable(
                    columns=[
                        ft.DataColumn(ft.Text("Host/URL", weight="bold")),
                        ft.DataColumn(ft.Text("Status", weight="bold")),
                        ft.DataColumn(ft.Text("Details", weight="bold")),
                        ft.DataColumn(ft.Text("Delete", weight="bold")),
                    ],
                    rows=[
                        ft.DataRow(
                            cells=[
                                ft.DataCell(ft.Text("(Example) example.com", color=ft.Colors.GREY_600)),
                                ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                                ft.DataCell(ft.Text("Blocked for reason A, B, C...", color=ft.Colors.GREY_600)),
                                ft.DataCell(ft.IconButton(icon=ft.Icons.DELETE, icon_color=ft.Colors.GREY_600, disabled=True)),
                            ]
                        )
                    ],
                    heading_row_height=50,
                    expand=True
                ),
                ft.TextButton("Manage Full Blacklist", icon=ft.Icons.ARROW_FORWARD, icon_color=ft.Colors.PRIMARY, on_click= lambda e: self.page.go("/blacklist")),
            ],
            spacing=15, 
            scroll=ft.ScrollMode.AUTO,
          )

        return [
            CustomCard(conn_controls),
            CustomCard(protocol_controls),
            CustomCard(redirect_controls),
            CustomCard(blacklist_controls) 
        ]
    
    def handle_toggle_proxy(self, e: ft.ControlEvent):
        # change ui to laoding
        self.status_text.value = "CONNECTING..."
        self.loading_ring.visible = True
        self.page.update()

        # connection to iject server -> proxy
        if e.control.value: # client tries to connect
            self.page.inject_server.start_inject_server(change_ui_when_finished=self.set_status)
        else:
            self.page.inject_server.stop(change_ui_when_finished=self.set_status)

    def set_status(self, status : bool, details: str | None=None):
        self.status_text.value = details or None
        if status:
            # status text
            if not self.status_text.value:
                self.status_text.value = "CONNECTED TO PROXY"
            self.status_text.color = ft.Colors.GREEN
            self.toggle_btn.value = True
            self.page.session.set("is_connected", True)
            # loading bar
            self.loading_ring.visible = False
        
        else:
            # status text
            if not self.status_text.value:
                self.status_text.value = "DISCONNECTED"
            self.status_text.color = ft.Colors.GREY
            self.toggle_btn.value = False
            self.page.session.set("is_connected", False)

            # loading bar
            self.loading_ring.visible = False
        
        self.page.update()
            
def main(page: ft.Page):
    ClientHomeView(page)
    page.update()

if __name__ == "__main__":
    # import logging
    # logging.basicConfig(level=logging.WARNING)
    ft.app(target=main)