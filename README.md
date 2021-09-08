# Класс FetchViaJwt

FetchViaJwt создана для авторизованных запросов к серверу с использованием авторизации на основе ключей (токенов) JWT.
Реализованы стандартные методы - get, post, put, delete.

## Обновления
	v1.1.0 - в объект, 
    который передается во второй параметр конструктора добавлены два поля: 
    BeforeHandlers, AfterHandlers


##  Параметры конструктора
- @param {string} **JwtRefreshUrl** адрес для запроса обновления токенов, это обязательный параметр, но если в объекте настройки передана фцнкция fetchTokens, то здесь может быть пустая строка 
- @param {object} params объект с настройками экземпляра FetchViaJwt:
> **JwtAccessTokenName** {string} под этим именем долежен приходить с сервера и будет сохранятться access-токен, по умолчанию JWT_ACCESS_TOKEN_NAME = "BEARER"

> **JwtRefreshTokenName** {string} под этим именем долежен приходить с сервера и будет сохранятться refresh-токен, по умолчанию JWT_REFRESH_TOKEN_NAME = "REFRESH"

> **getAccessToken** {function} можно передать функцию получения access-токена, по умолчанию берет из cookie 

> **setAccessToken** {function} можно передать функцию установки access-токена, по умолчанию помещает в cookie

> **getRefreshToken** {function} можно передать функцию получения refresh-токена, по умолчанию берет из localStorage

> **setRefreshToken** {function} можно передать функцию установки refresh-токена, по умолчанию помещает в localStorage

> **fetchTokens** {function} можно передать функцию запроса к api обновления токенов, должна вернуть промис содержащий объект с парой новых ключей 

> **MaxCallCount** {number} ограничение на кол-во неудачных попыток запроса токенов, по умолчанию 3

> **BeforeHandlers** {array} массив функций, вызываемых перед каждым запросом

> **AfterHandlers** {array} массив функций, вызываемых после каждого запроса, аргументом в нее будет передаваться объект ответа от сервера

## Что умеет 
Эта библиотека предназначена для работы с уже полученными токенами. 
Она умеет включать существующие токены в заголовки для запроса к страницам, которые требуют авторизацию.
Обновляет Access-токен, если он просрочен на основании Refres-токена и указанной страницы обновления.
Так же FetchViaJwt предназначена для CORS-запросов.

## Что НЕ делает
FetchViaJwt не предназначена для для начальной авторизации.
Login и инициализация JWT должны производится заранее.

Внимание!!!
Библиотека находится на стадии разработки, и может меняться.

## Пример
```js
// адрес для обновления токенов, если Access-токен просрочен
const JWT_REFRESH_URL = "https://www.site.ru/refresh_tokens";
// ключ, под которым в объектах и в cookie хранится Access-токен
const JWT_ACCESS_TOKEN_NAME = "MyBEARER";
// ключ, под которым в объектах и в cookie хранится Refresh-токен
const JWT_REFRESH_TOKEN_NAME = "MyREFRESH";

// создаем объект FetchViaJwt
const $fetch = new FetchViaJwt(
  JWT_REFRESH_URL,
  {
    JwtAccessTokenName: JWT_ACCESS_TOKEN_NAME,
    JwtRefreshTokenName: JWT_REFRESH_TOKEN_NAME,
  }
);

// адрес для получения данных методом POST
const POST_URL = "https://www.other-site-with-jwt-authorization.ru/data";
// флаг, указывающий, что произваодится чтение данных
let LoadFlag = true;
// объект данных
let Data;

// делаем POST-запрос с телом  { id: 12 }, 
// 3-м параметром можно указать дополнительные заголовки, если они разрешены на сайте CORS-политикой
// так же доступны методы get, put, delete 
$fetch.post(POST_URL, { id: 12 }) 
  .then((Resp) => {
    // после удачного запроса сохраняем данные
    Data = Resp;
    // для отладки выведем результат в консоль
    console.log("Resp ===> ", Resp);
  })
  .finally(() => {
    // при любом завершении запроса очищаем флаг загрузки
    LoadFlag=false;
  });

```