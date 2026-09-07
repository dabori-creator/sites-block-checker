import flet as ft
import asyncio
import aiohttp
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
        self.concurrent_checks = 5
        self.timeout = 4.0
        self.search_field = None
        self.log_container = None
        self.blocks_container = None
        self.stats_container = None
        self.sites_container = None


        self.load_config()
        
    def load_config(self):
        # Загрузка списка сайтов и текстов из YAML
        with open("config.yml", "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            self.sites = config.get("sites", [])
            self.translations = config.get("texts", {})

    def t(self, key):
        return self.translations[self.lang].get(key, key)

    # get ip and country
    async def get_ip_info(self):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('http://ip-api.com/json/', timeout=5) as response:
                    data = await response.json()
                    if data['status'] == 'success':
                        self.user_ip = data['query']
                        self.user_country = data['country']
                        self.user_city = data['city']
                        self.user_is = data['as']
                        self.ip_checked = True
                        # print (data)
                        return True
        except:
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
            "is_ru": domain.endswith(".ru") or site.get("flag", "") == "🇷🇺"
        }
        
        try:
            # DNS checking
            try:
                loop = asyncio.get_event_loop()
                ip = await loop.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
                if not ip:
                    result["status"] = "blocked"
                    result["block_type"] = "DNS Poisoning"
                    return result
                ip = ip[0][4][0]
                # for the strange reason RKN uses 127.0.0.2 for DNS Poisoning
                if not ip or ip == '0.0.0.0' or ip == '127.0.0.1' or ip == '127.0.0.2':
                    result["status"] = "blocked"
                    result["block_type"] = "DNS Poisoning"
                    return result
            except:
                print("Error DNS")
                result["status"] = "blocked"
                result["block_type"] = "DNS Poisoning"
                return result
            
            # HTTP checking
            try:
                connector = aiohttp.TCPConnector()
                async with aiohttp.ClientSession(connector=connector) as session:
                    try:
                        async with session.get(f"https://{domain}", timeout=self.timeout) as response:
                            if response.status < 400:
                                result["status"] = "OK"
                                result["block_type"] = "OK"
                            else:
                                result["status"] = "OK"
                                result["block_type"] = "HTTP STUB"
                    except asyncio.TimeoutError:
                        # Additional check using ping
                        try:
                            # ping 4 packets 4 sec timeout
                            process = await asyncio.create_subprocess_exec(
                                "ping", "-c", "4", "-w", "4", domain,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE
                            )
                            stdout, stderr = await process.communicate()
                            if process.returncode == 0:
                                result["status"] = "OK"
                                result["block_type"] = "OK"
                            else:
                                result["status"] = "blocked"
                                result["block_type"] = "IP Block"
                        except:
                            print("Ошибка IP")
                            result["status"] = "blocked"
                            result["block_type"] = "IP Block"
            except aiohttp.ClientError as e:
                if "SSL" in str(e) or "certificate" in str(e) or "ssl" in str(e):
                    result["status"] = "OK"
                    result["block_type"] = "SSL Error"
                else:
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
            return {"total": 0, "OK": 0, "http_error": 0, "ssl_error": 0, "dns_filter": 0, "ip_block": 0, "unknown_error": 0, "ru_available": 0, "ru_total": 0, "foreign_available": 0, "foreign_total": 0}
        
        total = len(self.results)

        OK = sum(1 for r in self.results.values() if r["status"] == "OK")
        http_error = sum(1 for r in self.results.values() if r["block_type"] == "HTTP STUB")
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
                    ft.Text(f"{stats['OK']}", size=28, weight=ft.FontWeight.BOLD, color=ft.Colors.GREEN_600),
                    ft.Text("OK", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_200)
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=20,
                width=150
            )
        )

        # http error
        self.blocks_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text(f"{stats['http_error']}", size=28, weight=ft.FontWeight.BOLD, color=ft.Colors.PINK_600),
                    ft.Text("HTTP STUB", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_200)
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=20,
                width=150
            )
        )

        # ssl error
        self.blocks_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text(f"{stats['ssl_error']}", size=28, weight=ft.FontWeight.BOLD, color=ft.Colors.CYAN_600),
                    ft.Text("SSL Error", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_200)
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=20,
                width=150
            )
        )

        # DNS Poisoning
        self.blocks_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text(f"{stats['dns_filter']}", size=28, weight=ft.FontWeight.BOLD, color=ft.Colors.PURPLE_ACCENT_400),
                    ft.Text("DNS Poisoning", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_200)
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=20,
                width=150
            )
        )
        # IP Block
        self.blocks_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text(f"{stats['ip_block']}", size=28, weight=ft.FontWeight.BOLD, color=ft.Colors.RED_600),
                    ft.Text("IP Block", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_200)
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=20,
                width=150
            )
        )

        self.blocks_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text(f"{stats['unknown_error']}", size=28, weight=ft.FontWeight.BOLD, color=ft.Colors.ORANGE_ACCENT_400),
                    ft.Text("Unknown Error", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.GREY_200)
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=20,
                width=150
            )
        )
        
        # Все сайты
        total_pct = (stats["OK"] / stats["total"] * 100) if stats["total"] > 0 else 0
        self.stats_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text("Все сайты", size=14, weight=ft.FontWeight.BOLD),
                    ft.Text(f"{stats['OK']}/{stats['total']}", size=16),
                    ft.Text(f"{total_pct:.1f}%", size=20, color=ft.Colors.GREEN_600 if total_pct > 50 else (ft.Colors.ORANGE_600 if (total_pct < 50 and total_pct > 15) else ft.Colors.RED_600))
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=20,
                width=150
            )
        )
        
        # .ru сайты
        ru_pct = (stats["ru_available"] / stats["ru_total"] * 100) if stats["ru_total"] > 0 else 0
        self.stats_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text("Сайты .ru", size=14, weight=ft.FontWeight.BOLD),
                    ft.Text(f"{stats['ru_available']}/{stats['ru_total']}", size=16),
                    ft.Text(f"{ru_pct:.1f}%", size=20, color=ft.Colors.GREEN_400 if ru_pct > 50 else (ft.Colors.ORANGE_400 if (ru_pct < 50 and ru_pct > 15) else ft.Colors.RED_400))
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=20,
                width=150
            )
        )
        
        # Зарубежные сайты
        foreign_pct = (stats["foreign_available"] / stats["foreign_total"] * 100) if stats["foreign_total"] > 0 else 0
        self.stats_container.controls.append(
            ft.Container(
                content=ft.Column([
                    ft.Text("Зарубежные", size=14, weight=ft.FontWeight.BOLD),
                    ft.Text(f"{stats['foreign_available']}/{stats['foreign_total']}", size=16),
                    ft.Text(f"{foreign_pct:.1f}%", size=20, color=ft.Colors.GREEN_400 if foreign_pct > 50 else (ft.Colors.ORANGE_400 if (foreign_pct < 50 and foreign_pct > 15) else ft.Colors.RED_400))
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                bgcolor=ft.Colors.GREY_900,
                border_radius=10,
                padding=20,
                width=150
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
                ft.Text("Нет данных для отображения", size=16)
            )
            if self.page:
                self.page.update()

            return
        
        for domain, result in self.results.items():
            status_text = "✓ OK" if (result["status"] == "OK" and result["status"] == None) else f"✗ {result['block_type']}"
            match result['block_type']:
                case "OK":
                    status_color = ft.Colors.GREEN_600
                case "HTTP STUB":
                    status_color = ft.Colors.PINK_600
                case "SSL Error":
                    status_color = ft.Colors.CYAN_600
                case "DNS Poisoning":
                    status_color = ft.Colors.PURPLE_ACCENT_400
                case "IP Block":
                    status_color = ft.Colors.RED_600
                case "Unknown Error":
                    status_color = ft.Colors.ORANGE_ACCENT_400
                case _:
                    status_color = ft.Colors.ORANGE_400
            
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
        ft.Window.width = 1380
        ft.Window.resizable = False

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
            content=ft.Text("Проверить IP"),
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=2), alignment=ft.Alignment.CENTER),
            on_click=lambda e: asyncio.create_task(check_ip())
        )
        
        start_btn = ft.Button(
            content=ft.Text(self.t('start_check')),
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=2), alignment=ft.Alignment.CENTER),
            on_click=lambda e: asyncio.create_task(start_check()),
            width=1200,
            expand=True
        )
        
        progress_bar = ft.ProgressBar(width=1200, visible=False, color="amber", expand=True)
        progress_text = ft.Text("", size=14)
        
        # Статистика
        stats_container = ft.Row(
            wrap=True,
            spacing=10,
            controls=[]
        )
        self.stats_container = stats_container
        
        # Карточки сайтов
        sites_container = ft.Row(
            wrap=True,
            spacing=10,
            controls=[]
        )
        self.sites_container = sites_container

        # Карточки сайтов
        blocks_container = ft.Row(
            wrap=True,
            spacing=10,
            controls=[]
        )
        self.blocks_container = blocks_container
        
        # Лог с поиском
        search_field = ft.TextField(
            hint_text="Поиск...",
            border=ft.Border.all(1, ft.Colors.GREY_400),
            width=1200,
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

        # Кнопки смены языка
        lang_change = ft.Button(
            content=ft.Text("RU" if self.lang == "ru" else "EN"),
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=4), padding=15),
            on_click=lambda e: self.update_ui_texts()
        )

        def on_hover(e):
            if e.data == "true":
                container.scale = ft.transform.Scale(1.1)  # Увеличиваем на 30%
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
                warnings.append("⚠️ Не удалось определить IP-адрес")
            
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
            progress_text.value = "Начинаем проверку..."
            page.update()
            
            def update_progress(pct):
                progress_bar.value = pct
                progress_text.value = f"Проверено: {int(pct * len(self.sites))}/{len(self.sites)}"
                page.update()
            
            # Запуск проверки
            await self.check_all_sites(update_progress)
            
            # Обновление интерфейса
            self.update_stats()
            self.update_site_cards()
            self.update_log()
            
            progress_bar.visible = True
            progress_text.value = "Проверка завершена!"
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
            ft.Text("ПОСЛЕДНИЕ ПРОВЕРКИ", size=20, weight=ft.FontWeight.BOLD),
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