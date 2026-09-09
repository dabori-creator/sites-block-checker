import flet as ft
from flet import Page, Text, Button
import asyncio
import aiohttp
import aiodns
from aiohttp.resolver import AsyncResolver
import socket
import subprocess
import yaml
import re
import requests
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import concurrent.futures


class SiteChecker:
    def __init__(self):
        self.page = None
        self.sites = []
        self.results = {}
        self.logs = []
        self.lang = "ru"
        self.texts = {}
        self.user_ip = None
        self.user_country = None
        self.user_city = None
        self.user_is = None
        self.ip_checked = False
        self.concurrent_checks = 10
        self.timeout = 3.0
        self.search_field = None
        self.log_container = None
        self.blocks_container = None
        self.stats_container = None
        self.sites_container = None
        self.additional_dns = ["8.8.8.8", "9.9.9.9"]
        self.http_stub_list = ["доступ ограничен",
                              "доступ к запрашиваемому ресурсу",
                              "по решению роскомнадзора",
                              "решением суда",
                              "заблокирован по",
                              "blocked by roskomnadzor",
                              "blocked by rkn",
                              "rkn.gov.ru/org/register",
                              "единый реестр",
                              "доступ запрещен"]

        self.load_config()
        self.load_texts()
        self.load_sites()
        
    def load_config(self):
        with open("config.yml", "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            self.config = config.get("config", [])
            self.lang = self.config["lang"]
            self.concurrent_checks = self.config["concurrent_checks"]
            self.timeout = self.config["timeout"]
            self.additional_dns = self.config["additional_dns"]


    def load_texts(self):
        with open("texts.yml", "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            self.translations = config.get("texts", {})

    def load_sites(self):
        with open("sites.yml", "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            self.sites = config.get("sites", [])


    def t(self, key):
        return self.translations[self.lang].get(key, key)

    # get ip
    async def get_ip_info(self):
        ip_connector = aiohttp.TCPConnector(limit=5, force_close=False) 
        try:
            async with aiohttp.ClientSession(connector=ip_connector) as session:
                async with session.get('http://ip-api.com/json/', timeout=50) as response:
                    data = await response.json()
                    if data['status'] == 'success':
                        self.user_ip = data['query']
                        self.user_country = data['country']
                        self.user_city = data['city']
                        self.user_is = data['as']
                        self.ip_checked = True
                        return True
        except Exception as e:
            ip_connector = aiohttp.TCPConnector(limit=5, force_close=False) 
            try:
                async with aiohttp.ClientSession(connector=ip_connector) as session:
                    async with session.get('https://ident.me/json', timeout=50) as response:
                        data = await response.json()
                        if data['ip'] != None:
                            self.user_ip = data['ip']
                            self.user_country = data['country']
                            self.user_city = data['city']
                            self.user_is = data['aso']
                            self.ip_checked = True
                            return True
            except Exception as e:
                print (e)
                self.user_ip = "Не удалось определить"
                self.user_country = "Не удалось определить"
                self.ip_checked = False
            return False

    def update_log(self):
        if not self.search_field or not self.log_container:
            return
            
        search_text = self.search_field.value.lower()
        self.log_container.controls.clear()
        
        for log_entry in self.logs:
            if search_text == "" or search_text in log_entry.lower():
                self.log_container.controls.append(ft.Text(log_entry, size=12))
        
        if self.page:
            self.page.update()
    
    async def check_site(self, site: dict) -> dict:
        domain = site["d"]
        result = {
            "domain": domain,
            "name": site.get("name", domain),
            "flag": site.get("flag", ""),
            "status": "unknown",
            "block_type": None,
            "is_ru": domain.endswith(".ru") or domain.endswith(".рф") or site.get("flag", "") == "🇷🇺"
        }
        
        try:
             # HTTP checking
            try:
                connector = aiohttp.TCPConnector()
                async with aiohttp.ClientSession(connector=connector) as session:
                    try:
                        async with session.get(f"https://{domain}", timeout=self.timeout) as response:
                            if response.status < 400:
                                html_data = await response.text()
                                for value in self.http_stub_list:
                                    if value in html_data:
                                        result["status"] = "blocked"
                                        result["block_type"] = "HTTP STUB"
                                        print(html_data)
                                    else:
                                        result["status"] = "OK"
                                        result["block_type"] = "OK"
                            else: 
                                result["status"] = "OK"
                                result["block_type"] = "HTTP ERROR"
                    except asyncio.TimeoutError:
                            try:
                                additional_resolver = AsyncResolver(nameservers=self.additional_dns)
                                conn = aiohttp.TCPConnector(resolver=additional_resolver)
                                async with aiohttp.ClientSession(connector=conn) as sess:
                                    try:
                                        async with sess.get(f"https://{domain}", timeout=self.timeout) as resp:
                                            if resp.status > 0:
                                                result["status"] = "blocked"
                                                result["block_type"] = "DNS Poisoning"
                                    except asyncio.TimeoutError:
                                        result["status"] = "blocked"
                                        result["block_type"] = "IP Block"
                            except Exception as e:
                                if "Domain name not found" in str(e) or "DNS server returned general failure" in str(e) or "Указанное сетевое имя более недоступно" in str(e):
                                    result["status"] = "blocked"
                                    result["block_type"] = "DNS Poisoning"
                                else:
                                    print(str(e) + "1111")          
            except Exception as e:
                if "Domain name not found" in str(e) or "DNS server returned general failure" in str(e) or "Указанное сетевое имя более недоступно" in str(e):
                    result["status"] = "blocked"
                    result["block_type"] = "DNS Poisoning"
                elif "certificate verify failed" in str(e) or "CERTIFICATE_VERIFY_FAILED" in str(e) or "self-signed certificate in certificate chain" in str(e):
                    result["status"] = "OK"
                    result["block_type"] = "SSL Error"
                elif "Удаленный компьютер отклонил это сетевое подключение" in str(e) or "remote computer refused" in str(e):
                    result["status"] = "blocked"
                    result["block_type"] = "IP Block"
                else:
                    print(str(e))
                    result["status"] = "blocked"
                    result["block_type"] = "DPI"


            except aiohttp.ClientError as e:
                print(str(e))
                result["status"] = "blocked"
                result["block_type"] = "Unknown Error"                 
            return result  
        except Exception as e:
            print(e)
            result["status"] = "blocked"
            result["block_type"] = "Ошибка проверки"
            return result

    
    async def check_all_sites(self, progress_callback=None):
        self.results = {}
        self.logs = []
        
        total = len(self.sites)
        checked = 0
        
        # Divide into groups for parallel checking
        for i in range(0, len(self.sites), self.concurrent_checks):
            batch = self.sites[i:i+self.concurrent_checks]
            tasks = [self.check_site(site) for site in batch]
            results = await asyncio.gather(*tasks)
            
            for site, result in zip(batch, results):
                self.results[site["d"]] = result
                self.logs.append(f"{site['name']} ({site['d']}): {result['block_type']}")
                
                checked += 1
                if progress_callback:
                    progress_callback(checked / total)
                    # Update the log after each check
                    if self.page:
                        self.update_log()
                        self.update_stats()
                        self.update_site_cards()

    
        return self.results
    
    def get_stats(self):
        # Obtaining statistics for checked sites
        if not self.results:
            return {"total": 0, "OK": 0, "http_error": 0, "http_stub": 0, "ssl_error": 0, "dns_filter": 0, "ip_block": 0, "unknown_error": 0, "ru_available": 0, "ru_total": 0, "foreign_available": 0, "foreign_total": 0}
        
        total = len(self.results)

        OK = sum(1 for r in self.results.values() if r["status"] == "OK")
        http_stub = sum(1 for r in self.results.values() if r["block_type"] == "HTTP STUB")
        http_error = sum(1 for r in self.results.values() if r["block_type"] == "HTTP ERROR")
        ssl_error = sum(1 for r in self.results.values() if r["block_type"] == "SSL Error")
        dns_filter = sum(1 for r in self.results.values() if r["block_type"] == "DNS Poisoning")
        ip_block = sum(1 for r in self.results.values() if r["block_type"] == "IP Block")
        unknown_error = sum(1 for r in self.results.values() if r["block_type"] == "Unknown Error")

        
        ru_total = sum(1 for r in self.results.values() if r.get("is_ru", False))
        ru_available = sum(1 for r in self.results.values() if r.get("is_ru", False) and r["status"] == "OK")
        
        foreign_total = total - ru_total
        foreign_available = OK - ru_available
        
        return {
            "total": total,
            "OK": OK,
            "http_error": http_error,
            "http_stub": http_stub,
            "ssl_error": ssl_error,
            "dns_filter" : dns_filter,
            "ip_block": ip_block,
            "unknown_error": unknown_error,
            "ru_total": ru_total,
            "ru_available": ru_available,
            "foreign_total": foreign_total,
            "foreign_available": foreign_available
        }
   
    def update_stats(self):
        if not self.stats_container:
            return

        if not self.blocks_container:
            return
            
        stats = self.get_stats()
        self.stats_container.controls.clear()
        self.blocks_container.controls.clear()
        
        if stats["total"] == 0:
            self.stats_container.controls.append(
                ft.Container(
                    content=ft.Text("Нет данных", size=16),
                    bgcolor=ft.Colors.GREY_800,
                    border_radius=10,
                    padding=20
                )
            )
            if self.page:
                self.page.update()
            return

        available_pct = (stats["OK"]) if stats["total"] > 0 else 0
        self.blocks_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text(f"{stats['OK']}", size=28, weight=ft.FontWeight.BOLD, color=ft.Colors.GREEN_400),
                    ft.Text("OK", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_200)
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=20,
                width=170
            )
        )

        # http error
        self.blocks_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text(f"{stats['http_error']}", size=28, weight=ft.FontWeight.BOLD, color=ft.Colors.ORANGE_ACCENT_400),
                    ft.Text("HTTP ERROR", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_200)
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=20,
                width=170
            )
        )

        # http stub
        self.blocks_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text(f"{stats['http_stub']}", size=28, weight=ft.FontWeight.BOLD, color=ft.Colors.PINK_600),
                    ft.Text("HTTP STUB", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_200)
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=20,
                width=170
            )
        )

        # ssl error
        self.blocks_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text(f"{stats['ssl_error']}", size=28, weight=ft.FontWeight.BOLD, color=ft.Colors.CYAN_600),
                    ft.Text("SSL ERROR", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_200)
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=20,
                width=170
            )
        )

        # DNS Poisoning
        self.blocks_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text(f"{stats['dns_filter']}", size=28, weight=ft.FontWeight.BOLD, color=ft.Colors.PURPLE_ACCENT_400),
                    ft.Text("DNS POISONING", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_200)
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=20,
                width=170
            )
        )
        # IP Block
        self.blocks_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text(f"{stats['ip_block']}", size=28, weight=ft.FontWeight.BOLD, color=ft.Colors.RED_400),
                    ft.Text("IP BLOCK", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_200)
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=20,
                width=170
            )
        )

        self.blocks_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text(f"{stats['unknown_error']}", size=28, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_600),
                    ft.Text("UNKNOWN ERROR", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_200)
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=20,
                width=170
            )
        )
        
        total_pct = (stats["OK"] / stats["total"] * 100) if stats["total"] > 0 else 0
        self.stats_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text(self.t('all_sites'), size=14, weight=ft.FontWeight.BOLD),
                    ft.Text(f"{stats['OK']}/{stats['total']}", size=16),
                    ft.Text(f"{total_pct:.1f}%", size=20, color=ft.Colors.GREEN_400 if total_pct > 50 else (ft.Colors.ORANGE_400 if (total_pct <= 50 and total_pct > 15) else ft.Colors.RED_400))
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=10,
                width=170
            )
        )
        
        # .ru sites
        ru_pct = (stats["ru_available"] / stats["ru_total"] * 100) if stats["ru_total"] > 0 else 0
        self.stats_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text(self.t('ru_sites'), size=14, weight=ft.FontWeight.BOLD),
                    ft.Text(f"{stats['ru_available']}/{stats['ru_total']}", size=16),
                    ft.Text(f"{ru_pct:.1f}%", size=20, color=ft.Colors.GREEN_400 if ru_pct > 50 else (ft.Colors.ORANGE_400 if (ru_pct <= 50 and ru_pct > 15) else ft.Colors.RED_400))
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=10,
                width=170
            )
        )
        
        foreign_pct = (stats["foreign_available"] / stats["foreign_total"] * 100) if stats["foreign_total"] > 0 else 0
        self.stats_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text(self.t('not_ru_sites'), size=14, weight=ft.FontWeight.BOLD),
                    ft.Text(f"{stats['foreign_available']}/{stats['foreign_total']}", size=16),
                    ft.Text(f"{foreign_pct:.1f}%", size=20, color=ft.Colors.GREEN_400 if foreign_pct > 50 else (ft.Colors.ORANGE_400 if (foreign_pct <= 50 and foreign_pct > 15) else ft.Colors.RED_400))
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=10,
                width=170
            )
        )
        
        if self.page:
            self.page.update()


    def update_ui_texts(self):
        self.lang = 'en' if self.lang == 'ru' else 'ru'
        self.page.title = self.t('title')
        # start_btn.content=ft.Text(self.t('start_check'))
        self.page.clean()
        self.main(self.page)
        if self.page:
                self.page.update()
    
    def update_site_cards(self):
        if not self.sites_container:
            return
            
        self.sites_container.controls.clear()
        
        if not self.results:
            self.sites_container.controls.append(
                ft.Text("No data to render", size=16)
            )
            if self.page:
                self.page.update()

            return
        
        for domain, result in self.results.items():
            status_text = "✓ OK" if (result["status"] == "OK" and result["status"] == None) else f"✗ {result['block_type']}"
            match result['block_type']:
                case "OK":
                    status_color = ft.Colors.GREEN_400
                case "HTTP ERROR":
                    status_color = ft.Colors.ORANGE_ACCENT_400
                case "HTTP STUB":
                    status_color = ft.Colors.PINK_600
                case "SSL Error":
                    status_color = ft.Colors.CYAN_600
                case "DNS Poisoning":
                    status_color = ft.Colors.PURPLE_ACCENT_400
                case "IP Block":
                    status_color = ft.Colors.RED_400
                case "Unknown Error":
                    status_color = ft.Colors.GREY_600
                case _:
                    status_color = ft.Colors.BLUE_400
            
            self.sites_container.controls.append(
                ft.Container(
                    content=ft.Column([
                        ft.Text(f"{result.get('flag', '')} {result.get('name', domain)}", size=12, weight=ft.FontWeight.BOLD),
                        ft.Text(domain, size=10, color=ft.Colors.GREY_400),
                        ft.Text(status_text, size=13, color=status_color)
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=5),
                    bgcolor=ft.Colors.GREY_800,
                    border_radius=5,
                    padding=10,
                    width=150,
                    height=100,
                    border=ft.Border.all(2, status_color),
                    animate_scale=ft.Animation(300, ft.AnimationCurve.EASE_IN_OUT),
                    scale=ft.Scale(1.0)
                )
            )
        
        if self.page:
            self.page.update()

    def main(self, page: ft.Page):
        self.page = page
        self.page.title = self.t('title')
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.padding = 10
        self.page.scroll = ft.ScrollMode.AUTO
        # self.page.min_width=1580
        ft.Window.width = 1480
        ft.Window.resizable = True

        try:
            with open("config.yml", "r", encoding="utf-8") as f:
                pass
        except FileNotFoundError:
            # page.show_dialog(config_dialog)
            with open('error.log', 'a', encoding='utf-8') as f:
                f.write("Config file not found")
        
        # Элементы интерфейса
        ip_status = ft.Text("", size=14)
        is_status = ft.Text("", size=14)
        location_status = ft.Text("", size=14)
        ip_check_btn = ft.Button(
            content=ft.Text(self.t('check_ip')),
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=2), alignment=ft.Alignment.CENTER),
            on_click=lambda e: asyncio.create_task(check_ip())
        )
        
        start_btn = ft.Button(
            content=ft.Text(self.t('start_check')),
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=2), alignment=ft.Alignment.CENTER),
            on_click=lambda e: asyncio.create_task(start_check()),
            width=1300,
            expand=True
        )
        
        progress_bar = ft.ProgressBar(width=1200, visible=False, color="amber", expand=True)
        progress_text = ft.Text("", size=14)
        
        stats_container = ft.Row(
            wrap=True,
            spacing=10,
            controls=[]
        )
        self.stats_container = stats_container
        
        sites_container = ft.Row(
            wrap=True,
            spacing=10,
            controls=[]
        )
        self.sites_container = sites_container

        blocks_container = ft.Row(
            wrap=True,
            spacing=10,
            controls=[]
        )
        self.blocks_container = blocks_container
        
        # Лог с поиском
        search_field = ft.TextField(
            hint_text=self.t('search'),
            border=ft.Border.all(1, ft.Colors.GREY_400),
            width=1300,
            expand=True,
            on_change=lambda e: self.update_log()
        )
        self.search_field = search_field
        
        log_container = ft.Column(
            spacing=2,
            height=200,
            expand=True,
            size_change_interval=100,
            scroll=ft.ScrollMode.AUTO,
            controls=[]
        )
        self.log_container = log_container
        
        log_area = ft.Container(
            content=log_container,
            border=ft.Border.all(1, ft.Colors.GREY_400),
            expand=True,
            size_change_interval=100,
            border_radius=5,
            padding=10,
        )

        lang_change = ft.Button(
            content=ft.Text("RU" if self.lang == "ru" else "EN"),
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=4), padding=15),
            on_click=lambda e: self.update_ui_texts()
        )

        def on_hover(e):
            if e.data == "true":
                container.scale = ft.transform.Scale(1.1)
            else:
                container.scale = ft.transform.Scale(1.0)
            container.update()

        def update_stats_wrapper():
            self.update_stats()
        
        def update_site_cards_wrapper():
            self.update_site_cards()
        
        async def check_ip():
            await self.get_ip_info()
            update_ip_status()
            
            # change text color if country isn't Russia
            warnings = []
            if self.user_country != "Russia":
                warnings.append(f"⚠️ {self.user_country}")
            if not self.ip_checked:
                warnings.append("⚠️ ", self.t('ip_failed'))
            
            if warnings:
                ip_status.value = f"IP: {self.user_ip}"
                is_status.value = f"IS: {self.user_is}"
                location_status.value = f"Country: {self.user_country}"
                # ip_status.value = f"IP: {self.user_ip} | {', '.join(warnings)}"
                ip_status.color = ft.Colors.ORANGE_400
                is_status.color = ft.Colors.ORANGE_400
                location_status.color = ft.Colors.ORANGE_400
            else:
                ip_status.value = f"IP: {self.user_ip}"
                is_status.value = f"IS: {self.user_is}"
                location_status.value = f"Country: {self.user_country}"
                ip_status.color = ft.Colors.GREEN_400
                is_status.color = ft.Colors.GREEN_400
                location_status.color = ft.Colors.GREEN_400
            
            page.update()
        
        # Check ip status
        def update_ip_status():
            if not self.ip_checked:
                ip_status.value = "IP не проверен"
                ip_status.color = ft.Colors.GREY_400
                return
            
            if self.user_country != "RU" or self.user_ip == "Не удалось определить":
                ip_status.color = ft.Colors.ORANGE_400
            else:
                ip_status.color = ft.Colors.GREEN_400
        
        # Start sites checking
        async def start_check():
            if not self.ip_checked:
                await check_ip()
            
            start_btn.disabled = True
            progress_bar.visible = True
            progress_text.value = self.t('starting_check')
            page.update()
            
            def update_progress(pct):
                progress_bar.value = pct
                progress_text.value = self.t('checked')+ ": " + f"{int(pct * len(self.sites))}/{len(self.sites)}"
                page.update()
            
            # Запуск проверки
            await self.check_all_sites(update_progress)
            
            # Обновление интерфейса
            self.update_stats()
            self.update_site_cards()
            self.update_log()
            
            progress_bar.visible = False
            progress_text.value = self.t('check_finish')
            start_btn.disabled = False
            page.update()
        
        # Компоновка интерфейса
        page.add(
            # Верхняя панель с языком и IP
            ft.Row([
                ft.Row([
                    ip_check_btn,
                ], alignment=ft.MainAxisAlignment.START),
                ft.Row([
                    ft.Column([
                        ft.Row([
                            ip_status
                        ], spacing=5, expand=True),
                        ft.Row([
                            is_status
                        ], spacing=5, expand=True),
                        ft.Row([
                            location_status
                        ], spacing=5, expand=True)
                    ], alignment=ft.MainAxisAlignment.CENTER),
                ], alignment=ft.MainAxisAlignment.CENTER),
                # ft.Row([
                #     lang_change
                # ], alignment=ft.MainAxisAlignment.END),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            
            ft.Divider(height=3),
            
            # Кнопка запуска и прогресс
            ft.Row([
                ft.Column([
                    ft.Row([
                        start_btn,
                    ], spacing=10, expand=True),
                    ft.Row([
                        progress_text,
                    ], spacing=10, expand=True),
                    ft.Row([
                        progress_bar
                    ], spacing=10, expand=True)
                ], alignment=ft.MainAxisAlignment.CENTER, expand=True),
            ], alignment=ft.MainAxisAlignment.CENTER, expand=True),
            
            
            # Статистика
            ft.Row([blocks_container,
            ], alignment=ft.MainAxisAlignment.CENTER, expand=True),

            ft.Row([stats_container,
            ], alignment=ft.MainAxisAlignment.CENTER, expand=True),
            
            sites_container,
            
            # Лог
            ft.Text(self.t('last_checks'), size=20, weight=ft.FontWeight.BOLD),
            ft.Column([
                ft.Row([
                    search_field,
                ], spacing=10, expand=True),
                ft.Row([
                    log_area
                ], spacing=10, expand=True),
            ], spacing=10, expand=True)
        )
        
        # Автоматическая проверка IP при запуске
        asyncio.create_task(check_ip())

if __name__ == "__main__":
    checker = SiteChecker()
    ft.run(checker.main)