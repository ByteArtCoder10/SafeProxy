import flet as ft

from ....logs.logger import client_logger
from src.client.ui.controls.custom_controls import CustomTextField, CustomBtn, CustomCard, CardTitle, CustomPageHeader, CustomAlertDialog, CustomPopUpModal
# --Backend imports--
from ....core.authentication.auth_handler import RspStatus, FailReason

class BlackListView:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.snack_bar = ft.SnackBar(ft.Text())
        
        # modals
        self.add_host_modal = CustomPopUpModal(on_submit=self._add_host)
        self._delete_all_alert_modal = CustomAlertDialog("Delete All BlackLised Hosts",
            "Are you sure you want to delete all? this action cannot be undone.",
            yes_value="Delete",
            no_value="Cancel",
            on_click_yes=self._delete_all,
            on_click_no=self._close_dialog
        )
        
        self.page.overlay.append(self.add_host_modal)
        self.page.overlay.append(self._delete_all_alert_modal)
        
        # controls
        header = CustomPageHeader("BlackList")
        
        # btns
        btns = ft.Row(
            controls=[
                CustomBtn(text="Add Host", on_click=self.add_host_modal.open, bg_color=ft.Colors.WHITE, text_color=ft.Colors.PRIMARY, elevation=2),
                CustomBtn(text="Delete All", on_click=self._open_dialog, bg_color=ft.Colors.WHITE, text_color=ft.Colors.RED, elevation=2),
            ],
            alignment=ft.MainAxisAlignment.CENTER
        )
        

        # table
        self.blacklist_table = ft.DataTable(
        columns=[
            ft.DataColumn(label=ft.Text("Host/URL", weight="bold")),
            ft.DataColumn(label=ft.Text("Status", weight="bold")),
            ft.DataColumn(label=ft.Container(ft.Text("Details", weight="bold"), width=400)),
            ft.DataColumn(label=ft.Text("Delete", weight="bold"))
        ],
        rows=[
            ],
            data_row_min_height=40,
            data_row_max_height=float("inf"),
            expand=True
        )
        
        # layout
        layout = ft.Column(
            controls=[header, btns, self.blacklist_table],
            scroll=ft.ScrollMode.AUTO
        )
        self.content = ft.ResponsiveRow(
            controls= [layout],
            height=self.page.height,
            alignment=ft.MainAxisAlignment.CENTER,
            expand=True    
        )

        self._populate_table()
    
    def _open_dialog(self, e):
        self._delete_all_alert_modal.open = True
        self.page.update()

    def _close_dialog(self, e):
        self._delete_all_alert_modal.open = False
        self.page.update()
    def _edit(self):
        pass
    def _delete(self):
        pass
    
    def _populate_table(self):
        # get blackist of user from server
        rsp = self.page.auth_handler.get_blacklist(self.page.session.get("username"))
        if rsp.status == RspStatus.SUCCESS:
            client_logger.info(f"Server's repsonse: {rsp.__dict__}")
            blacklist_dict = rsp.blacklist
        else:
            self.show_snackbar(f"Error - Failed fetching your blacklist: {rsp.fail_reason.value}")
            return

        data_rows_list=[]
        for host, details in blacklist_dict.items():
            data_rows_list.append(
                    ft.DataRow(
                        cells=[
                            ft.DataCell(
                                # contaienr so it doesnt overlfow
                                ft.Container(
                                    content=ft.Text(host, overflow=ft.TextOverflow.CLIP),
                                    width=350, # Limits width to force wrap
                            
                                    padding=ft.padding.symmetric(vertical=5),
                                )   
                            ),
                            ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                            ft.DataCell(
                                # contaienr so it doesnt overlfow
                                ft.Container(
                                    content=ft.Text(details, overflow=ft.TextOverflow.CLIP),
                                    width=350, # Limits width to force wrap
                                    padding=ft.padding.symmetric(vertical=5),
                                )   
                            ),
                            ft.DataCell(
                                ft.IconButton(
                                    icon=ft.Icons.DELETE,
                                    icon_color=ft.Colors.RED_600,
                                    selected_icon_color=ft.Colors.RED,
                                    on_click=lambda e, h=host: self._delete_host(e, h)
                                )
                            )
                        ]
                        )
            )
        
        self.blacklist_table.rows = data_rows_list
        self.page.update()

    def _add_host(self, e : ft.ControlEvent):
        host = self.add_host_modal.input_field.value.strip()
        details = self.add_host_modal.details_field.value.strip()
        # first validate fields
        if host == "" or not host:
            return
        
        host = self._sanitize_host(host)

        # DB request to add 
        rsp = self.page.auth_handler.add_blacklist_host(self.page.session.get("username"), host, details)
        
        # handle response and it's effects on UI
        if rsp.status == RspStatus.SUCCESS:
            # add host to datatable
            self.blacklist_table.rows.append(
                ft.DataRow(
                    cells=[
                        ft.DataCell(
                            ft.Container(
                                content=ft.Text(host, overflow=ft.TextOverflow.CLIP),
                                width=350,
                                padding=ft.padding.symmetric(vertical=5),  
                            )
                        ),
                        ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                        ft.DataCell(
                            ft.Container(
                                content=ft.Text(details, overflow=ft.TextOverflow.CLIP),
                                width=350,
                                padding=ft.padding.symmetric(vertical=5),  
                            )
                        ),
                        ft.DataCell(
                            ft.IconButton(
                                icon=ft.Icons.DELETE,
                                icon_color=ft.Colors.RED_600,
                                selected_icon_color=ft.Colors.RED,
                                on_click=lambda e, h=host: self._delete_host(e, h)
                            )
                        )

                ]
                )
            )

            self.show_snackbar(f"Successfully added {host} to your blacklist!", is_error=False)
        else:
            self.show_snackbar(f"Error - {rsp.fail_reason.value}")
        
        self.add_host_modal.close()
        self.page.update()
    
    def _sanitize_host(self, host : str) -> str:
        if host.startswith("https://www."):
            return host[12:]
        if host.startswith("http://www."):
            return host[11:]
        if host.startswith("https://"):
            return host[8:]
        if host.startswith("http://"):
            return host[7:]
        if host.startswith("www."):
            return host[4:]
        return host
    
    def _delete_host(self, e : ft.ControlEvent, host : str):
        
        rsp = self.page.auth_handler.delete_blacklist_host(self.page.session.get("username"), host)

        if rsp.status == RspStatus.SUCCESS:
            self.blacklist_table.rows = [row for row in self.blacklist_table.rows if row.cells[0].content.content.value != host]
        
            self.show_snackbar(f"Successfully deleted {host} from your blacklist", is_error=False)
        else:
            self.show_snackbar(f"Error - {rsp.fail_reason.value}",)
        
        self.page.update()
    
    def _delete_all(self, e=None):
        # delete
        rsp = self.page.auth_handler.delete_full_blacklist(self.page.session.get("username"))

        if rsp.status == RspStatus.SUCCESS:
            self.blacklist_table.rows = []
            
            self.show_snackbar("Successfully deleted all blacklist.", is_error=False)
        else:
            self.show_snackbar(f"Error - {rsp.fail_reason.value}")
        self.page.update()
        self._close_dialog(e)

    def show_snackbar(self, msg : str, is_error : bool = True):
        sb = self.page.snack_bar

        sb.content = ft.Text(msg)
        sb.bgcolor = ft.Colors.RED_ACCENT_700 if is_error else ft.Colors.GREEN_ACCENT_700
        sb.open = True
        sb.duration = 4000

        self.page.update()

    
    def get_content(self) -> ft.ResponsiveRow:
        return self.content
    