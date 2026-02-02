import flet as ft
from ..utils.layoutBuilder import LayoutBuilder
from ..views.auth.loginView import LoginView
from ..views.auth.signupView import SignUpView
from ..views.client.clientHomeView import ClientHomeView
from ..views.client.blackListView import BlackListView
from ..views.client.CAView import CAView
from ..views.client.accountView import AccountView
class ViewRouter:
    """
    Manages navigation.
    """
    
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.on_route_change = self._on_route_change
        self.page.on_view_pop = self._on_view_pop
        
        self.layout = LayoutBuilder(page)
        
        self.routes = {
            "/": LoginView, # default screen view is a login when opening the application
            "/login": LoginView,
            "/signup": SignUpView,
            "/client_home": ClientHomeView,
            "/blacklist": BlackListView,
            "/ca": CAView,
            "/account": AccountView
            # "/admin": AdminDashboardView 
        }

    def _on_route_change(self, e: ft.RouteChangeEvent):
        self.page.views.clear()
        route = e.route
        
        view_class = self.routes.get(route)
        
        if not view_class:
            content = ft.Text("404 - Page not found")
            view_type = "public"
        
        else:
            # create a viewinstance
            view_instance = view_class(self.page)
            content = view_instance.get_content()
            
            view_type = "public" if route in ["/", "/login", "/signup"] else "private"

        # decides by view_type if sidebar sohuld appear or not
        final_ui = self.layout.build(content, view_type, title=route)

        self.page.views.append(
            ft.View(
                route=route,
                controls=[final_ui],
                padding=0,
                spacing=0,
                bgcolor=ft.Colors.SURFACE
            )
        )
        self.page.update()

    def _on_view_pop(self, view):

        if len(self.page.views) > 1:
            self.page.views.pop()
            top_view = self.page.views[-1]
            self.page.go(top_view.route)