import flet as ft
from src.client.ui.controls.custom_controls import CustomTextField, CustomBtn, CustomCard, CardTitle, CustomPageHeader, CustomAlertDialog, CustomPopUpModal

class BlackListView:
    def __init__(self, page: ft.Page):
        self.page = page
        
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
        blacklist_table = ft.DataTable(
        columns=[
            ft.DataColumn(label=ft.Text("Host/URL", weight="bold")),
            ft.DataColumn(label=ft.Text("Status", weight="bold")),
            ft.DataColumn(label=ft.Container(ft.Text("Details", weight="bold"), width=400)),
            ft.DataColumn(label=ft.Text("Edit", weight="bold")),
            ft.DataColumn(label=ft.Text("Delete", weight="bold"))
        ],
        rows=[
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text("www.Hello.com")),
                    ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                    ft.DataCell(ft.Text("Blocks: -www.hello.comhello.com")),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.EDIT, icon_color=ft.Colors.GREY_600, selected_icon_color=ft.Colors.GREY)),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.DELETE, icon_color=ft.Colors.RED_600, selected_icon_color=ft.Colors.RED))
                ]
            ),
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text("www.Hello.com")),
                    ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                    ft.DataCell(ft.Text("Blocks:  www.hello.com/*  hello.com")),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.EDIT, icon_color=ft.Colors.GREY_600, selected_icon_color=ft.Colors.GREY)),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.DELETE, icon_color=ft.Colors.RED_600, selected_icon_color=ft.Colors.RED))
                ]
            ),
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text("www.Hello.com")),
                    ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                    ft.DataCell(ft.Text("Blocks:  www.hello.com/*  hello.com")),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.EDIT, icon_color=ft.Colors.GREY_600, selected_icon_color=ft.Colors.GREY, on_click=self._edit),),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.DELETE, icon_color=ft.Colors.RED_600, selected_icon_color=ft.Colors.RED, on_click=self._delete))
                ]
            ),
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text("www.Hello.com")),
                    ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                    ft.DataCell(ft.Text("Blocks:  www.hello.com/*  hello.com")),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.EDIT, icon_color=ft.Colors.GREY_600, selected_icon_color=ft.Colors.GREY)),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.DELETE, icon_color=ft.Colors.RED_600, selected_icon_color=ft.Colors.RED))
                ]
            ),
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text("www.Hello.com")),
                    ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                    ft.DataCell(ft.Text("Blocks:  www.hello.com/*  hello.com")),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.EDIT, icon_color=ft.Colors.GREY_600, selected_icon_color=ft.Colors.GREY)),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.DELETE, icon_color=ft.Colors.RED_600, selected_icon_color=ft.Colors.RED))
                ]
            ),
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text("www.Hello.com")),
                    ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                    ft.DataCell(ft.Text("Blocks:  www.hello.com/*  hello.com")),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.EDIT, icon_color=ft.Colors.GREY_600, selected_icon_color=ft.Colors.GREY)),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.DELETE, icon_color=ft.Colors.RED_600, selected_icon_color=ft.Colors.RED))
                ]
            ),
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text("www.Hello.com")),
                    ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                    ft.DataCell(ft.Text("Blocks:  www.hello.com/*  hello.com")),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.EDIT, icon_color=ft.Colors.GREY_600, selected_icon_color=ft.Colors.GREY)),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.DELETE, icon_color=ft.Colors.RED_600, selected_icon_color=ft.Colors.RED))
                ]
            ),
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text("www.Hello.com")),
                    ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                    ft.DataCell(ft.Text("Blocks: \n- www.hello.com/* \n- hello.com")),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.EDIT, icon_color=ft.Colors.GREY_600, selected_icon_color=ft.Colors.GREY)),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.DELETE, icon_color=ft.Colors.RED_600, selected_icon_color=ft.Colors.RED))
                ]
            ),
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text("www.Hello.com")),
                    ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                    ft.DataCell(ft.Text("Blocks: \n- www.hello.com/* \n- hello.com")),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.EDIT, icon_color=ft.Colors.GREY_600, selected_icon_color=ft.Colors.GREY)),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.DELETE, icon_color=ft.Colors.RED_600, selected_icon_color=ft.Colors.RED))
                ]
            ),
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text("www.Hello.com")),
                    ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                    ft.DataCell(ft.Text("Blocks: \n- www.hello.com/* \n- hello.com")),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.EDIT, icon_color=ft.Colors.GREY_600, selected_icon_color=ft.Colors.GREY)),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.DELETE, icon_color=ft.Colors.RED_600, selected_icon_color=ft.Colors.RED))
                ]
            ),
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text("www.Hello.com")),
                    ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                    ft.DataCell(ft.Text("Blocks: \n- www.hello.com/* \n- hello.com")),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.EDIT, icon_color=ft.Colors.GREY_600, selected_icon_color=ft.Colors.GREY)),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.DELETE, icon_color=ft.Colors.RED_600, selected_icon_color=ft.Colors.RED))
                ]
            ),
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text("www.Hello.com")),
                    ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                    ft.DataCell(ft.Text("Blocks: \n- www.hello.com/* \n- hello.com")),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.EDIT, icon_color=ft.Colors.GREY_600, selected_icon_color=ft.Colors.GREY)),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.DELETE, icon_color=ft.Colors.RED_600, selected_icon_color=ft.Colors.RED))
                ]
            ),
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text("www.Hello.com")),
                    ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                    ft.DataCell(ft.Text("Blocks: \n- www.hello.com/* \n- hello.com")),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.EDIT, icon_color=ft.Colors.GREY_600, selected_icon_color=ft.Colors.GREY)),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.DELETE, icon_color=ft.Colors.RED_600, selected_icon_color=ft.Colors.RED))
                ]
            ),
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text("www.Hello.com")),
                    ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                    ft.DataCell(ft.Text("Blocks: \n- www.hello.com/* \n- hello.com")),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.EDIT, icon_color=ft.Colors.GREY_600, selected_icon_color=ft.Colors.GREY)),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.DELETE, icon_color=ft.Colors.RED_600, selected_icon_color=ft.Colors.RED))
                ]
            ),
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text("www.Hello.com")),
                    ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                    ft.DataCell(ft.Text("Blocks: \n- www.hello.com/* \n- hello.com")),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.EDIT, icon_color=ft.Colors.GREY_600, selected_icon_color=ft.Colors.GREY)),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.DELETE, icon_color=ft.Colors.RED_600, selected_icon_color=ft.Colors.RED))
                ]
            ),
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text("www.Hello.com")),
                    ft.DataCell(ft.Text("BLOCKED", color=ft.Colors.RED)),
                    ft.DataCell(ft.Text("Blocks:  www.hello.com/*  hello.com")),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.EDIT, icon_color=ft.Colors.GREY_600, selected_icon_color=ft.Colors.GREY)),
                    ft.DataCell(ft.IconButton(icon=ft.Icons.DELETE, icon_color=ft.Colors.RED_600, selected_icon_color=ft.Colors.RED))
                ]
            ),

            ],
            expand=True
        )
        
        # layout
        layout = ft.Column(
            controls=[header, btns, blacklist_table],
            scroll=ft.ScrollMode.AUTO
        )
        self.content = ft.ResponsiveRow(
            controls= [layout],
            height=self.page.height,
            alignment=ft.MainAxisAlignment.CENTER,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            expand=True    
        )
    
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
 
    def _add_host(self):
        pass
    def _delete_all(self, e=None):
        # delete
        self._close_dialog(e)
        pass
    def get_content(self) -> ft.ResponsiveRow:
        return self.content
    