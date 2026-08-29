#!/usr/bin/env python3
# header_scan.py
# =============================================================================
# HEADER SCAN — аудит security-заголовков HTTP-ответа
# Автор: m2xdev
# Лицензия: MIT
#
# ДАННЫЙ КОД ПРЕДОСТАВЛЯЕТСЯ "КАК ЕСТЬ", БЕЗ ГАРАНТИЙ.
# АВТОР НЕ НЕСЁТ ОТВЕТСТВЕННОСТИ ЗА ЛЮБОЙ УЩЕРБ.
#
# Зависимости: pip install requests
# =============================================================================

from __future__ import annotations

import sys
from typing import Dict, List, Optional
from dataclasses import dataclass, field

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[!] requests не установлен. Установите: pip install requests")


# =============================================================================
# ЧТО ПРОВЕРЯЕМ
# =============================================================================

# Каждый заголовок: (имя, вес в оценке, краткое описание)
SECURITY_HEADERS = [
    ("Strict-Transport-Security", 20, "Заставляет браузер всегда использовать HTTPS"),
    ("Content-Security-Policy", 25, "Ограничивает источники скриптов/стилей — защита от XSS"),
    ("X-Frame-Options", 15, "Защита от clickjacking (встраивания сайта в iframe)"),
    ("X-Content-Type-Options", 10, "Запрещает браузеру угадывать MIME-тип (nosniff)"),
    ("Referrer-Policy", 10, "Контролирует, какой Referer отправляется на другие сайты"),
    ("Permissions-Policy", 10, "Ограничивает доступ к камере/геолокации/микрофону и т.д."),
    ("X-XSS-Protection", 5, "Устаревший, но иногда всё ещё встречается заголовок защиты от XSS"),
    ("Set-Cookie", 5, "Проверяем наличие Secure/HttpOnly/SameSite у кук (см. отдельно)"),
]


@dataclass
class HeaderResult:
    name: str
    present: bool
    value: Optional[str] = None
    description: str = ""


@dataclass
class ScanReport:
    url: str
    status_code: Optional[int] = None
    score: int = 0
    max_score: int = 100
    grade: str = "F"
    headers: List[HeaderResult] = field(default_factory=list)
    cookie_issues: List[str] = field(default_factory=list)
    error: Optional[str] = None


# =============================================================================
# ОСНОВНОЙ КЛАСС
# =============================================================================

class HeaderScanner:
    """
    Проверяет публично доступные security-заголовки сайта.

    Делает один обычный GET-запрос — то же самое, что делает браузер
    при обычном открытии страницы. Никакого перехвата или воздействия
    на сайт, только чтение того, что сервер сам отдаёт всем подряд.
    """

    def __init__(self, timeout: int = 10, user_agent: str = "header-scan/1.0"):
        self.timeout = timeout
        self.headers = {"User-Agent": user_agent}

    def scan(self, url: str) -> ScanReport:
        """Сканирует один URL и возвращает отчёт."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        report = ScanReport(url=url)

        if not REQUESTS_AVAILABLE:
            report.error = "requests не установлен"
            return report

        try:
            resp = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
        except requests.exceptions.RequestException as e:
            report.error = f"Не удалось подключиться: {e}"
            return report

        report.status_code = resp.status_code

        score = 0
        for name, weight, desc in SECURITY_HEADERS:
            if name == "Set-Cookie":
                continue  # обрабатываем отдельно ниже
            present = name in resp.headers
            value = resp.headers.get(name)
            report.headers.append(HeaderResult(name, present, value, desc))
            if present:
                score += weight

        # Отдельная проверка флагов у Set-Cookie
        set_cookie_weight = next(w for n, w, _ in SECURITY_HEADERS if n == "Set-Cookie")
        cookies_raw = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw.headers, "get_all") else resp.headers.get("Set-Cookie")
        if cookies_raw:
            cookie_list = cookies_raw if isinstance(cookies_raw, list) else [cookies_raw]
            all_flags_ok = True
            for c in cookie_list:
                c_lower = c.lower()
                if "secure" not in c_lower:
                    report.cookie_issues.append(f"Кука без флага Secure: {c.split('=')[0]}")
                    all_flags_ok = False
                if "httponly" not in c_lower:
                    report.cookie_issues.append(f"Кука без флага HttpOnly: {c.split('=')[0]}")
                    all_flags_ok = False
                if "samesite" not in c_lower:
                    report.cookie_issues.append(f"Кука без флага SameSite: {c.split('=')[0]}")
                    all_flags_ok = False
            if all_flags_ok:
                score += set_cookie_weight
        else:
            # Кук нет — нечего проверять, не штрафуем
            score += set_cookie_weight

        report.score = score
        report.max_score = sum(w for _, w, _ in SECURITY_HEADERS)
        report.grade = self._grade(report.score, report.max_score)
        return report

    @staticmethod
    def _grade(score: int, max_score: int) -> str:
        pct = (score / max_score) * 100 if max_score else 0
        if pct >= 90:
            return "A"
        elif pct >= 75:
            return "B"
        elif pct >= 60:
            return "C"
        elif pct >= 40:
            return "D"
        return "F"

    def print_report(self, report: ScanReport):
        """Печатает отчёт в консоль в читаемом виде."""
        print(f"\n{'=' * 60}")
        print(f"Отчёт: {report.url}")
        print("=" * 60)

        if report.error:
            print(f"[!] Ошибка: {report.error}")
            return

        print(f"HTTP статус: {report.status_code}")
        print(f"Оценка: {report.score}/{report.max_score} (грейд: {report.grade})\n")

        for h in report.headers:
            mark = "✅" if h.present else "❌"
            print(f"  {mark} {h.name}")
            print(f"     {h.description}")
            if h.present:
                print(f"     Значение: {h.value}")
            print()

        if report.cookie_issues:
            print("⚠️  Проблемы с куками:")
            for issue in report.cookie_issues:
                print(f"   - {issue}")
        print("=" * 60)


# =============================================================================
# SELF-TEST
# =============================================================================

def _run_tests() -> None:
    """
    Внутренние тесты. Требуют интернет-соединение, т.к. реально
    обращаются к публичным сайтам (это не мок, а живая проверка).
    """
    print("🛡️  КАПИБАРА ТЕСТИРУЕТ HEADER SCAN")
    print("=" * 62)

    passed = 0
    failed = 0

    def check(name: str, condition: bool) -> None:
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  ✅ {name}")
        else:
            failed += 1
            print(f"  ❌ {name}")

    scanner = HeaderScanner()

    # 1. Известный сайт с хорошими security-заголовками
    report = scanner.scan("https://github.com")
    check("github.com отвечает без ошибки", report.error is None)
    check("github.com получил ненулевой score", report.score > 0)
    check("грейд определён корректно (A-F)", report.grade in ["A", "B", "C", "D", "F"])

    # 2. Некорректный/несуществующий домен
    report_bad = scanner.scan("https://this-domain-definitely-does-not-exist-12345.com")
    check("несуществующий домен даёт ошибку, не падает", report_bad.error is not None)

    # 3. URL без схемы — должен сам добавить https://
    report_no_scheme = scanner.scan("github.com")
    check("URL без схемы обрабатывается", report_no_scheme.url.startswith("https://"))

    print("=" * 62)
    print(f"Результат: {passed} прошло, {failed} упало")
    if failed == 0:
        print("🎉 ВСЕ ТЕСТЫ ПРОШЛИ!")
    else:
        print("⚠️  ЕСТЬ ПАДЕНИЯ — капибара расстроена 😿")


# =============================================================================
# CLI
# =============================================================================

def main():
    if len(sys.argv) < 2:
        print("Использование:")
        print("  python header_scan.py <url>       - просканировать сайт")
        print("  python header_scan.py --test       - запустить self-test")
        return

    if sys.argv[1] == "--test":
        _run_tests()
        return

    url = sys.argv[1]
    scanner = HeaderScanner()
    report = scanner.scan(url)
    scanner.print_report(report)


if __name__ == "__main__":
    main()