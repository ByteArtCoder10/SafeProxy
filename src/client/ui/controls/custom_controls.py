import flet as ft
from enum import Enum
class CustomTextField(ft.TextField):
    def __init__(self, 
                *,
                label_text=None,
                hint_text=None, 
                field_width=130,
                password=False,
                icon_name=None,
                border_focused_color=ft.Colors.PRIMARY,
                on_change=None,
                **kwargs
                ):
        
        super().__init__(
            label=label_text,
            hint_text=hint_text,
            icon=icon_name,
            width=field_width,
            focused_border_color=border_focused_color,
            password=password,
            border_radius=10,
            on_change=on_change,
            **kwargs)

class CustomBtn(ft.Button):
    def __init__(self,
                *,
                text=None,
                on_click=None,
                width=300,
                height=50,
                bg_color=ft.Colors.PRIMARY,
                text_color=ft.Colors.ON_PRIMARY,
                **kwargs):
        
        super().__init__(
            text=text,
            on_click=on_click,
            width=width,
            height=height,
            bgcolor=bg_color,
            color=text_color,
            **kwargs)
        # create rounded shaped btn
        self.style = ft.ButtonStyle(
            shape=ft.RoundedRectangleBorder(radius=10)
        )

class CustomCard(ft.Card):
    """Unified Card wrapper for consistent styling."""
    def __init__(self, content_control, height=None, bg_color=ft.Colors.SURFACE, **kwargs):
        super().__init__(
            elevation=4,
            color=bg_color,
            height=height,
            **kwargs
        )
        
        # one card when size is xs/sm and md/lg two cards per row
        self.col={"xs": 12, "sm": 12, "md": 6, "lg": 6}

        self.content=ft.Container(
            content=content_control,
            padding=20,)    
        
class CardTitle(ft.Column):
    """represents title with a divider used inside cards."""
    def __init__(self, title, color=ft.Colors.PRIMARY):
        super().__init__(spacing=5)

        self.controls = [
            ft.Text(title, weight=ft.FontWeight.BOLD, color=color, size=18),
            ft.Divider(height=1, color=ft.Colors.with_opacity(0.1, color)),
        ]

class CustomPageHeader(ft.Container):  
    def __init__(self, text: str):
        super().__init__()
        self.content=ft.Column(
            controls=[
                ft.Text(text, size=32, weight="bold", color=ft.Colors.PRIMARY),
                ft.Divider(color=ft.Colors.with_opacity(0.3, ft.Colors.PRIMARY))
            ], spacing=5)
        self.margin=ft.margin.only(bottom=20)
        self.col={"xs": 12} # always takes full width - even when the window is small

class SideBar(ft.NavigationRail):

    routeConvertor = {
        "/client_home": 0,
        "/blacklist": 1,
        "/ca": 2,
        "/account": 3
    } # assigns each attribute an incremnting integer vlaue to mathc selected_index

    def __init__(self, is_admin=False, route="/client_home"):
        super().__init__(
            width=150,
            bgcolor = ft.Colors.SURFACE_TINT
        )

        self.selected_index= SideBar.routeConvertor.get(route, 0)
        self.on_change = self.change_route
        if is_admin:
            self.destinations= [
                ft.NavigationRailDestination(
                    icon=ft.Icon(ft.Icons.DASHBOARD_OUTLINED),
                    selected_icon=ft.Icon(ft.Icons.DASHBOARD),
                    label="Dashboard",
                ),
                ft.NavigationRailDestination(
                    icon=ft.Icon(ft.Icons.CREATE_OUTLINED),
                    selected_icon=ft.Icon(ft.Icons.CREATE),
                    label="Logs",
                ),
                ft.NavigationRailDestination(
                    icon=ft.Icon(ft.Icons.INSERT_DRIVE_FILE_OUTLINED),
                    selected_icon=ft.Icon(ft.Icons.INSERT_DRIVE_FILE),
                    label="Certs",
                ),
                ft.NavigationRailDestination(
                    icon=ft.Icon(ft.Icons.ACCOUNT_CIRCLE_OUTLINED),
                    selected_icon=ft.Icon(ft.Icons.ACCOUNT_CIRCLE),
                    label="Account",
                )
            ]
        
        else:
            self.destinations= [
                ft.NavigationRailDestination(
                    icon=ft.Icon(ft.Icons.HOME_OUTLINED),
                    selected_icon=ft.Icon(ft.Icons.HOME),
                    label="Home",
                ),
                ft.NavigationRailDestination(
                    icon=ft.Icon(ft.CupertinoIcons.SQUARE_LIST),
                    selected_icon=ft.Icon(ft.CupertinoIcons.SQUARE_LIST_FILL),
                    label="BlackList",
                ),
                ft.NavigationRailDestination(
                    icon=ft.Icon(ft.Icons.SECURITY_OUTLINED),
                    selected_icon=ft.Icon(ft.Icons.SECURITY),
                    label="CA",
                ),
                ft.NavigationRailDestination(
                    icon=ft.Icon(ft.Icons.ACCOUNT_CIRCLE_OUTLINED),
                    selected_icon=ft.Icon(ft.Icons.ACCOUNT_CIRCLE),
                    label="Account",
                )
            ]

    def change_route(self, e : ft.ControlEvent):
        index =  e.control.selected_index

        if index ==0:
            self.page.go(f"/client_home")
        if index ==1:
            self.page.go(f"/blacklist")
        elif index ==2:
            self.page.go(f"/ca")
        elif index ==3:
            self.page.go(f"/account")

        self.selected_index =index

class CustomAlertDialog(ft.AlertDialog):

    def __init__(self, title: str, content : str, yes_value : str, on_click_yes, no_value : str | None = None, on_click_no=None, modal=True, only_yes=False):
        super().__init__(modal=modal)

        self.title = ft.Text(title, weight="bold")
        self.content=ft.Text(content)

        if only_yes:
            self.actions=[
                ft.TextButton(yes_value, on_click=on_click_yes),
            ]
        else:    
            self.actions=[
                ft.TextButton(yes_value, on_click=on_click_yes),
                ft.TextButton(no_value, on_click=on_click_no),
            ]


class CustomPopUpModal(ft.Container):
    def __init__(self, on_submit):
        super().__init__()
        self.on_submit_func = on_submit
        self.visible = False
        self.expand = True
        self.alignment = ft.alignment.center
        self.bgcolor = ft.Colors.with_opacity(0.6, "black")
        
        self.title_text = ft.Text(value="Add New Blacklist Host/URL", size=24, weight="bold")
        self.input_field = CustomTextField(label_text="Enter Host/URL", field_width=400)
        self.details_field = CustomTextField(
            label_text="Details",
            field_width=400,
            multiline=True, 
            min_lines=3, 
            max_lines=5,
        )

        self.content = ft.Container(
            width=400,
            padding=15,
            bgcolor=ft.Colors.WHITE,
            border_radius=15,
            shadow=ft.BoxShadow(blur_radius=20),
            content=ft.Column([
                ft.Row([
                    self.title_text,
                    ft.IconButton(ft.Icons.CLOSE, on_click=self.close, icon_color=ft.Colors.RED)
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                
                ft.Divider(),
                
                self.input_field,
                self.details_field,
                
                ft.Divider(),
                
                ft.Row([
                    ft.TextButton("Set", on_click=self.on_submit_func),
                    ft.TextButton("Cancel", on_click=self.close),
                ], 
                alignment=ft.MainAxisAlignment.END)
            ], spacing=15, tight=True)
        )

    def open(self, e=None):
        
        self.visible = True
        self.update()
   
    def close(self, e=None):
        # reset input fields values
        self.input_field.value = ""
        self.details_field.value = ""
        self.visible = False
        self.update()

