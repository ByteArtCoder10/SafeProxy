import flet as ft
import threading

from ...controls.custom_controls import CustomTextField, CustomBtn, CustomCard, CardTitle, CustomPageHeader, CustomAlertDialog
from ....core.authentication.auth_handler import RspStatus, FailReason
from ....core.ca_check.CA_handler import CAHandler
from ....core.inject_server.inject_server import InjectServer
from ....logs.logger import client_logger
class ClientHomeView:
    def __init__(self, page: ft.Page):
        self.page = page
        self.username = self.page.session.get("username") or "Client"
        self.page.inject_server = InjectServer(self.page.session.get("jwt_token"))

        # 1. Create a Loading State container
        self.loading_container = ft.Container(
            content=ft.Column([
                ft.ProgressRing(width=50, height=50, stroke_width=4 ,color=ft.Colors.PRIMARY),
                ft.Text("Syncing with SafeProxy server...", size=16, color=ft.Colors.PRIMARY)
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, alignment=ft.MainAxisAlignment.CENTER),
            expand=True,
            alignment=ft.alignment.center
        )

        # Main content starts as the loader
        self.content = ft.Column(
            controls=[self.loading_container],
            scroll=ft.ScrollMode.AUTO,
            expand=True,
        )

        # 2. Run the initialization in a background thread
        threading.Thread(target=self._async_initialize, daemon=True).start()


    def _async_initialize(self):
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

        
        resp_row = ft.ResponsiveRow(
            controls=[header] + cards,
            height=self.page.height,
            alignment=ft.MainAxisAlignment.CENTER,
            vertical_alignment=ft.CrossAxisAlignment.CENTER

        )
        self.content.controls = [resp_row]
        self.page.update()

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
        self.initialize_radio_tls_terminate()
        protocol_controls = ft.Column(
            controls=[
                CardTitle("Tunneling Protocol"),
                self.radio_tls_terminate,
                ft.Text("TLS allows data inspection for better security.", size=12, color=ft.Colors.GREY_500),
                ft.Text("Note: TLS Termination requires SafeProxy CA installed.", size=11, color=ft.Colors.GREY_500)
            ], 
            spacing=15
        )

        # Redirection Card
        self.initialize_radio_google_redirect()
        redirect_controls = ft.Column(
            controls=[
                CardTitle("Redirection Strategy"),
                self.radio_google_redirect,
                ft.Text("Handles invalid host requests automatically.", size=12, color=ft.Colors.GREY_500),
                ft.Text("Note: Google Redirect requires SafeProxy CA installed.", size=11, color=ft.Colors.GREY_500)
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

    def handle_change_tls_terminate(self, e: ft.ControlEvent):
        is_tls_terminate = True if e.control.value == "TLS" else False
        rsp = self.page.auth_handler.set_tls_terminate(self.page.session.get("username"), is_tls_terminate)
        if rsp.status == RspStatus.SUCCESS and is_tls_terminate:
            self.show_snackbar("Successfully changed your tunnling preference to TLS Termination", is_error=False)
            return
        if rsp.status == RspStatus.SUCCESS:
            self.show_snackbar("Successfully changed your tunnling preference to TCP tunneling", is_error=False)
            return
        
        self.show_snackbar(f"Failed changeing your tunnling preference - {rsp.fail_Reason.value}")
            
    def handle_change_google_redirect(self, e: ft.ControlEvent):
        is_google_redirect = True if e.control.value == "redirect" else False
        rsp = self.page.auth_handler.set_google_redirect(self.page.session.get("username"), is_google_redirect)
        if rsp.status == RspStatus.SUCCESS and is_google_redirect:
            self.show_snackbar("Successfully changed your redirection preference to Google Redirect", is_error=False)
            return
        if rsp.status == RspStatus.SUCCESS:
            self.show_snackbar("Successfully changed your redirection preference to 502 Bad Gateaway", is_error=False)
            return
        
        self.show_snackbar(f"Failed changeing your tunnling preference - {rsp.fail_Reason.value}")

    def initialize_radio_tls_terminate(self):
        self.tls_radio = ft.Radio(value="TLS", label="TLS Termination (Secure)", disabled=True)
        self.radio_tls_terminate = ft.RadioGroup(
            content=ft.Column([
                self.tls_radio,
                ft.Radio(value="TCP", label="TCP Tunnel (Raw)", ),
                ], 
                spacing=10
            ),
            on_change=self.handle_change_tls_terminate
        )
        
        # to show selection right away, even if it's goign to be changed ina couple of ms
        self.radio_tls_terminate.value = "TCP"
        
        # Up until this moment, didnt preform a startup_ca_check - because tls_terminate and google_redirect radios 
        # needed to be initalized for it to run.
        if not self.page.session.contains_key("CA_installed"):
            self.run_startup_ca_check()
        
        is_ca_installed = self.page.session.get("CA_installed")
        rsp = self.page.auth_handler.get_tls_terminate(self.username)
        
        # EDGE-CASES:
        # 1. ca_not_installed and DB-TCP (reasonable)
        # 2. ca_not_installed and DB-TLS (error - change db to TCP)
        # 3. ca_installed and DB-TCP (reasonable)
        # 4. ca_installed and DB-TLS (reasonable)
        # 5. ca_not_installed DB-ERROR - default to TCP + show error snackbar
        # 6. ca_installed DB-ERROR - default to TLS + show error snackbar

        match (rsp.status, is_ca_installed):
            
            # edge-case 5
            case (RspStatus.FAIL, False):
                self.radio_tls_terminate.value = "TCP"
                self.show_snackbar(f"Failed fetching your saved tunneling preference - {rsp.fail_reason.value}.\nDefaulting to TCP.", duration=10000)
            
            # edge-case 6
            case (RspStatus.FAIL, True):
                self.radio_tls_terminate.value = "TLS"
                self.show_snackbar(f"Failed fetching your saved tunneling preference - {rsp.fail_reason.value}.\nDefaulting to TLS.", duration=10000)
            
            # edge-cases 1 + 2
            case (RspStatus.SUCCESS, False):
                if rsp.tls_terminate:
                    self.radio_tls_terminate.value = "TCP"
                    
                    # *Try* changing DB preference to TCP
                    self.page.auth_handler.set_tls_terminate(self.username, False)
                    self.show_snackbar(f"SafeProxy can't TLS terminate if CA is not installed.\nIf you wish to continue with TLS Termination, please install SafeProxy CA.\nAs things stand, defaulting to TCP.", duration=10000)
       
                else: # edge case 1
                    self.radio_tls_terminate.value = "TCP"
            
            # edge-cases 3 + 4
            case (RspStatus.SUCCESS, True):
                self.tls_radio.disabled = False
                if rsp.tls_terminate:
                    self.radio_tls_terminate.value = "TLS"
                else:
                    self.radio_tls_terminate.value = "TCP"
        
        self.page.update()

    def initialize_radio_google_redirect(self):
        self.redirect_radio = ft.Radio(value="redirect", label="Smart Redirect (To Google Search)", disabled=True)
        self.radio_google_redirect = ft.RadioGroup(
            content=ft.Column([
                self.redirect_radio,
                ft.Radio(value="502_rsp", label="Send a 502 'Bad Gateaway' response"),
                ],
                spacing=10
            ),
            on_change=self.handle_change_google_redirect
        )
        
         # to show selection right away, even if it's goign to be changed ina couple of ms
        self.radio_google_redirect.value = "502_rsp"

        # check CA installed, and DB preference.
        is_ca_installed = self.page.session.get("CA_installed")
        rsp = self.page.auth_handler.get_google_redirect(self.username)
        
        # EDGE-CASES:
        # 1. ca_not_installed and DB-502 (reasonable)
        # 2. ca_not_installed and DB-REDIRECT (error - change db to 502)
        # 3. ca_installed and DB-502 (reasonable)
        # 4. ca_installed and DB-REDIRECT (reasonable)
        # 5. ca_not_installed DB-ERROR - default to 502 + show error snackbar
        # 6. ca_installed DB-ERROR - default to REDIRECT + show error snackbar

        match (rsp.status, is_ca_installed):
            
            # edge-case 5
            case (RspStatus.FAIL, False):
                self.radio_google_redirect.value = "502_rsp"
                self.show_snackbar(f"Failed fetching your saved redirection preference - {rsp.fail_reason.value}. Defaulting to 502 Bad Gateaway.")
            
            # edge-case 6
            case (RspStatus.FAIL, True):
                self.radio_google_redirect.value = "redirect"
                self.show_snackbar(f"Failed fetching your saved redirection preference - {rsp.fail_reason.value}. Defaulting to Google Redirect.")
            
            # edge-cases 1 + 2
            case (RspStatus.SUCCESS, False):
                if rsp.google_redirect:
                    self.radio_google_redirect.value = "502_rsp"
                    # *Try* changing DB preference to 502
                    self.page.auth_handler.set_google_redirect(self.username, False)

                    self.show_snackbar(f"SafeProxy can't Google Redirect if CA is not installed. If you wish to continue with Google Redirect, please install SafeProxy CA. As things stand, defaulting to 502 Bad Gateaway.")
       
                else: # edge case 2
                    self.radio_google_redirect.value = "502_rsp"
            
            # edge-cases 3 + 4
            case (RspStatus.SUCCESS, True):
                self.redirect_radio.disabled = False
                if rsp.google_redirect:
                    self.radio_google_redirect.value = "redirect"
                else:
                    self.radio_google_redirect.value = "502_rsp"
        
        self.page.update()  

    def show_snackbar(self, msg : str, is_error : bool = True, duration : int = 4000):
        sb = ft.SnackBar(
            content=ft.Text(msg),
            bgcolor=ft.Colors.RED_ACCENT_700 if is_error else ft.Colors.GREEN_ACCENT_700,
            duration=duration,
        )

        self.page.overlay.append(sb)
        sb.open = True
        
        self.page.update()
    
    def run_startup_ca_check(self):
    
        rsp = self.page.auth_handler.get_ca_cert()

        if rsp.status == RspStatus.SUCCESS:
            if not CAHandler.update_local_file(rsp.ca_cert):
                self.page.session.set("CA_installed", False) # we dont know it is actually installed - but need to disable install feature

                self._show_ca_modal(
                    title="SafeProxy CA certificate: Local update error",
                    details=
                    "SafeProxy updated it's root CA certificate, used for signing host certificates.\n" \
                    "At the moment, Installing the updated CA certifcate is not feasible, due to \n" \
                    "local CA certificate update failure. In order to prevent certificate rejection\n" \
                    "by your browser, automatically switching to TCP tunneling and disabling TLS.\n" \
                    "If you wish to use TLS Termination, please try to run the app again."
                )
                return
            
            if CAHandler.is_ca_cert_installed(rsp.ca_cert):
                self.page.session.set("CA_installed", True)
                return
            
            else:
                self.page.session.set("CA_installed", False)
                
                self._show_ca_modal(
                    title="SafeProxy CA certificate: Re-installation required",
                    details=
                    "SafeProxy updated it's root CA certificate (or your local CA certificate\n" \
                    "was changed), used for signing host certificates. As a result, in order to keep\n" \
                    "using TLS Termination tunneling preference (and Smart Redirect if on \n" \
                    "google-service-less chromium) You will need to install the updated certificate\n" \
                    "through the CA page." 
                )
        else:
            self.page.session.set("CA_installed", False) # we dont know it is actually installed - but need to disable install feature
            
            self._show_ca_modal(
                title="SafeProxy CA sync error", 
                details=
                "Failed getting SafeProxy's most up-to-date CA certificate, used for signing host \n" \
                "certificates. At the moment, In order to prevent certificate rejection by your browser, \n"
                "automatically switching to TCP tunneling and disabling TLS. If you wish to use TLS Termination \n" \
                "(and Smart Redirect if on google-service-less chromium), please try to run the app again."
            )

    def _force_secure_features_off(self, reason: str):
        """Function to put the UI in a safe state."""
        self.radio_tls_terminate.value = "TCP"
        self.tls_radio.disabled = True
        self.radio_google_redirect.value = "502_rsp"
        self.redirect_radio.disabled = True
        client_logger.info(f"Security features disabled: {reason}")
        self.page.update()

    def _show_ca_modal(self, title: str, details: str):
        def close_dialog(e: ft.ControlEvent):
            updated_ca_dialog.open = False
            self.page.update()

        updated_ca_dialog = CustomAlertDialog(
            title=title,
            content=details,    
            yes_value="OK",
            on_click_yes=close_dialog,
            only_yes=True
        )

        updated_ca_dialog.open = True
        self.page.overlay.append(updated_ca_dialog)
        self.page.update()

    def get_content(self) -> ft.Column:
        return self.content
    
def main(page: ft.Page):
    ClientHomeView(page)
    page.update()

if __name__ == "__main__":
    # import logging
    # logging.basicConfig(level=logging.WARNING)
    ft.app(target=main)