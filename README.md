# header-scan

Аудит security-заголовков HTTP-ответа сайта — CSP, HSTS, X-Frame-Options
и другие защитные заголовки, с оценкой и грейдом (A–F).

## Что это

Инструмент делает один обычный GET-запрос к сайту — то же самое, что делает
браузер при обычном открытии страницы — и проверяет, какие security-заголовки
сервер отдаёт в ответе. Никакого перехвата, подмены или воздействия на сайт —
только чтение публично доступных данных, которые сервер и так присылает всем.

## Что проверяется

| Заголовок | Зачем нужен |
|---|---|
| `Strict-Transport-Security` (HSTS) | Заставляет браузер всегда использовать HTTPS |
| `Content-Security-Policy` (CSP) | Ограничивает источники скриптов/стилей — защита от XSS |
| `X-Frame-Options` | Защита от clickjacking (встраивания сайта в iframe) |
| `X-Content-Type-Options` | Запрещает браузеру угадывать MIME-тип |
| `Referrer-Policy` | Контролирует, какой Referer уходит на другие сайты |
| `Permissions-Policy` | Ограничивает доступ к камере/геолокации/микрофону |
| `X-XSS-Protection` | Устаревший, но иногда всё ещё встречающийся заголовок |
| Флаги cookie | `Secure`, `HttpOnly`, `SameSite` у `Set-Cookie` |

## Установка

```bash
git clone https://github.com/m2xdev/header-scan
cd header-scan
pip install -r requirements.txt
```

## Использование

```bash
# Просканировать сайт
python header_scan.py github.com

# Запустить self-test (обращается к github.com для живой проверки)
python header_scan.py --test
```

Пример вывода:

```
============================================================
Отчёт: https://github.com
============================================================
HTTP статус: 200
Оценка: 85/100 (грейд: B)

  ✅ Strict-Transport-Security
     Заставляет браузер всегда использовать HTTPS
     Значение: max-age=31536000; includeSubdomains; preload
...
```

## Использование как библиотеки

```python
from header_scan import HeaderScanner

scanner = HeaderScanner()
report = scanner.scan("example.com")

print(report.grade)        # 'A', 'B', 'C', 'D' или 'F'
print(report.score)        # числовая оценка
print(report.cookie_issues)  # список проблем с флагами кук
```

## ⚠️ Дисклеймер / Disclaimer

### Русская версия

Инструмент делает только обычные, публично разрешённые HTTP-запросы —
то же самое, что делает любой браузер при открытии страницы. Он не
перехватывает трафик, не изменяет данные и не воздействует на сканируемый
сайт каким-либо образом.

Тем не менее, при массовом или автоматизированном сканировании множества
сайтов соблюдайте разумную частоту запросов (rate limiting) и уважайте
`robots.txt` и условия использования сканируемых ресурсов.

Программное обеспечение предоставляется **«КАК ЕСТЬ»**, без каких-либо
явных или подразумеваемых гарантий. Используя данный код, вы самостоятельно
несёте ответственность за его применение. Автор не несёт ответственности
за ущерб, возникший в результате использования данного ПО.

### English version

This tool makes only ordinary, publicly permitted HTTP requests — the same
kind of request any browser makes when opening a page. It does not intercept
traffic, modify data, or affect the scanned site in any way.

That said, when scanning many sites in bulk or automated fashion, use
reasonable rate limiting and respect `robots.txt` and the terms of service
of the sites you scan.

The software is provided **"AS IS"**, without warranty of any kind, express
or implied. By using this code, you are solely responsible for its use.
The author is not liable for any damages arising from the use of this
software.

## Связанные проекты

- [xss-shield](https://github.com/m2xdev/xss-shield) / [xss-lab](https://github.com/m2xdev/xss-lab)
- [query-sql](https://github.com/m2xdev/query-sql) / [query-lab](https://github.com/m2xdev/query-lab)
- [csrf-shield](https://github.com/m2xdev/csrf-shield) / [csrf-lab](https://github.com/m2xdev/csrf-lab)
- [mitm-shield](https://github.com/m2xdev/mitm-shield)