3. Повторная отправка проксированных запросов – 5 баллов
Не только проксировать запросы в п.1-2, но и сохранять их вместе с ответом в БД (SQL или NoSQL). 
Запросы необходимо сохранять в распаршеном виде (можно использовать любые библиотеки). Необходимо парсить:
HTTP метод (GET/POST/PUT/HEAD)
Путь и GET параметры
Заголовки, при этом отдельно парсить Cookie
Тело запроса, в случае application/x-www-form-urlencoded отдельно распасить POST параметры
Ответы необходимо сохранять также в распаршеном виде
Не забыть про gzip и другие методы сжатия! (можно либо расшифровывать их, либо изменять заголовки на стороне прокси)