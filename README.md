# Скрипт для анализа лог файлов сервера nginx
Проект создан в рамках обучения <a href="https://moodle.tsu.ru/course/view.php?id=22106" target="_blank" rel="noreferrer">Разработка программного обеспечения и скриптовые языки</a>. Использование открытого программного обеспечения при разработке геосервисов МИИГАиК.

Использованы следующие технологии и пакеты:
<p align="left"> 
<a href="https://www.python.org" target="_blank" rel="noreferrer"> <img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/python/python-original.svg" alt="python" width="40" height="40"> </a>
<a href="https://tqdm.github.io" target="_blank" rel="noreferrer"> <img src="https://tqdm.github.io/img/logo-trans.gif" alt="python" width="40" height="40"> </a>
</p>

<h3 align="left">Задание для студентов МИИГАиК - Вариант 2 (2024г):</h3>
Скрипт для анализа лог файлов сервера nginx. Определяет Top-20 подозрительных запросов.
Определение подозрительности может осуществляться на основе 4 признаков (принадлежность к определенному IP не является признаком). Запрос считается подозрительным при совпадении не менее двух признаков.

### Клонировать репозиторий и перейти в него:

```
git@github.com:erges699/tsu_nginx_log_analyzer.git
```

### Создать и активировать виртуальное окружение, установить в него зависимости:

```
$ python3.9 -m venv venv
$ . venv/bin/activate
$ python3 -m pip install --upgrade pip
$ pip install -r requirements.txt
```
### Запуск скрипта в терминале:

```
$ python3 nginx_log_analyzer.py access.log
```

<h3 align="left">Об авторе:</h3>
<a href="https://github.com/erges699" target="_blank">Сергей Баляба</a>
