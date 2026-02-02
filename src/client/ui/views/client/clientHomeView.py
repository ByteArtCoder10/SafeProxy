import flet as ft
from ...controls.custom_controls import CustomTextField, CustomBtn, CustomCard, CardTitle, CustomPageHeader


class ClientHomeView:
    def __init__(self, page: ft.Page):
        self.page = page
        self.username = self.page.session.get("username") or "Client"
        

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
        conn_controls = ft.Column(
            controls=[
                CardTitle("Connection Status"),
                ft.Column(
                    controls=[
                        ft.Row(controls=[ft.Text("Status:", weight="bold"), ft.Text("disconnected", color=ft.Colors.RED)]),
                        ft.Switch(
                            label="Activate Proxy    ",
                            active_color=ft.Colors.PRIMARY,
                            label_position=ft.LabelPosition.LEFT,
                            on_change=self.handle_toggle_proxy
                        ),
                ], 
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN
                ),
            ],
            spacing=15
        )
        print(1)
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
        print(2)

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
        print(3)

        # Blacklist Card
        blacklist_controls = ft.Column(
            controls=[
                CardTitle("Blacklisted Hosts/IPs"),
                ft.DataTable(
                    columns=[
                        ft.DataColumn(ft.Text("Host", weight="bold")),
                        ft.DataColumn(ft.Text("Expiry", weight="bold")),
                    ],
                    rows=[
                        ft.DataRow(cells=[ft.DataCell(ft.Text("fxp.com")), ft.DataCell(ft.Text("2025"))]),
                        ft.DataRow(cells=[ft.DataCell(ft.Text("data.cyber.co.il")), ft.DataCell(ft.Text("2026"))]),
                    ],
                    heading_row_height=35,
                    expand=True
                ),
                ft.TextButton("Manage Full Blacklist", icon=ft.Icons.ARROW_FORWARD, icon_color=ft.Colors.PRIMARY, on_click= lambda e: self.page.go("/blacklist")),
            ],
            spacing=15, 
            scroll=ft.ScrollMode.AUTO,
          )
        print(4)

        return [
            CustomCard(conn_controls),
            CustomCard(protocol_controls),
            CustomCard(redirect_controls),
            CustomCard(blacklist_controls) 
        ]
    
    def handle_toggle_proxy(self, e: ft.ControlEvent):    
        if e.control.value: # client tries to connect
            pass
        else:
            pass

def main(page: ft.Page):
    ClientHomeView(page)
    page.update()

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.WARNING)
    ft.app(target=main)