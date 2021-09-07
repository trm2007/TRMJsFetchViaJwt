import { debugPrint, generateGetUrl, checkFetchResponseStatus } from "TRMJsHelpers";
import { getCookie, setCookie } from "TRMJsCookies";

/**
 * короткоживущий многоразовый токен для получения данных
 */
export const JWT_ACCESS_TOKEN_NAME = 'BEARER';
/**
* долгоживущий одноразовый токен для обновления access_token
*/
export const JWT_REFRESH_TOKEN_NAME = 'REFRESH';
/**
 * ограничение на кол-во неудачных попыток запроса к API обновления токенов
 */
export const MAX_CALL_COUNT = 3;

/**
 * код проверки, что пользователь не авторизован
 */
const HTTP_UNAUTHORIZED_CODE = 401;

class Error401 extends Error {
  constructor(Message = "") {
    const Separator = Message ? " " : "";
    super(Message + Separator + "Access токен локально не обнаружен!");
    this.name = "Error401";
  }
}

export class ErrorMaxCallCount extends Error {
  constructor(Message = "") {
    const Separator = Message ? " " : "";
    super(Message + Separator + "Превышено количество допустимых попыток обновления токенов!");
    this.name = "ErrorMaxCallCount";
  }
}

export class FetchViaJwt {
  /**
   * 
   * @param {string} JwtRefreshUrl адрес для запроса обновления токенов, 
   * это обязательный параметр, но если в объекте настройки передана фцнкция fetchTokens, 
   * то здесь может быть пустая строка 
   * @param {object} params объект с настройками экземпляра FetchViaJwt: {
   * JwtAccessTokenName, // {string} под этим именем долежен приходить с сервера и будет сохранятться access-токен, по умолчанию JWT_ACCESS_TOKEN_NAME = "BEARER"
   * JwtRefreshTokenName, // {string} под этим именем долежен приходить с сервера и будет сохранятться refresh-токен, по умолчанию JWT_REFRESH_TOKEN_NAME = "REFRESH"
   * getAccessToken, // {function} можно передать функцию получения access-токена, по умолчанию берет из cookie 
   * setAccessToken, // {function} можно передать функцию установки access-токена, по умолчанию помещает в cookie
   * getRefreshToken, // {function} можно передать функцию получения refresh-токена, по умолчанию берет из localStorage
   * setRefreshToken, // {function} можно передать функцию установки refresh-токена, по умолчанию помещает в localStorage
   * fetchTokens, // {function} можно передать функцию запроса к api обновления токенов, должна вернуть промис содержащий объект с парой новых ключей 
   * MaxCallCount, // {number} ограничение на кол-во неудачных попыток запроса токенов, по умолчанию 3
   * } 
   */
  constructor(JwtRefreshUrl, {
    JwtAccessTokenName,
    JwtRefreshTokenName,
    getAccessToken,
    setAccessToken,
    getRefreshToken,
    setRefreshToken,
    fetchTokens,
    MaxCallCount,
  }) {
    this.JWT_REFRESH_URL = JwtRefreshUrl;

    this.MAX_CALL_COUNT = MaxCallCount || MAX_CALL_COUNT;
    this.JWT_ACCESS_TOKEN_NAME = JwtAccessTokenName || JWT_ACCESS_TOKEN_NAME;
    this.JWT_REFRESH_TOKEN_NAME = JwtRefreshTokenName || JWT_REFRESH_TOKEN_NAME;
    this.getAccessToken = getAccessToken || this.getAccessTokenDefault;
    this.setAccessToken = setAccessToken || this.setAccessTokenDefault;
    this.getRefreshToken = getRefreshToken || this.getRefreshTokenDefault;
    this.setRefreshToken = setRefreshToken || this.setRefreshTokenDefault;
    this.fetchTokens = fetchTokens || this.fetchTokensDefault;

    this.CommonHeaders = {};
  }

  /**
   * добавляет заголовки, которые будут устанавливаться с каждым запросом
   * 
   * @param {Object} Headers
   */
  addCommonHeaders(Headers) {
    this.CommonHeaders = Object.assign(this.CommonHeaders, Headers);
  }

  /**
   * получает данные методом POST с проверкой авторизации,
   * если Access токен просрочен, то повторно запрашивает JWT,
   * используя функцию fetchTokens,
   * если обновить токены не удалось
   * 
   * @param {string} Url 
   * @param {object} Data не обязательный параметр, объект с данными для POST-запроса, 
   * будет преобразован в JSON-строку - JSON.stringify(Data)
   * @param {object} Headers не обязательный параметр, объект с Http-заголовками для запроса
   * @param {number} Count служебный параметр - счетчик неудачных вызовов
   * @returns {Promise} промис, содержащий объект с данными
   */
  get(Url, Data = {}, Headers = {}, Count = 0) {
    // эта функция вызывает себя рекурсивно, прибавляя при каждом вызове 1 к Count
    // если кол-во превысит MAX_CALL_COUNT, то выбрасываем исключение
    if (Count >= this.MAX_CALL_COUNT) {
      throw new ErrorMaxCallCount("[FetchViaJwt.get]");
    }
    // вызываем getViaJwt, которая добавит все поля из Data к Url-запроса
    return this.getViaJwt(Url, Data, Headers)
      .then(this.onResponseCheck401)
      .catch(this.refreshTokensAndRepeatRequest(Url, Data, Headers, this.post, Count));
  }

  /**
   * получает данные методом POST с проверкой авторизации,
   * если Access токен просрочен, то повторно запрашивает JWT,
   * используя функцию fetchTokens,
   * если обновить токены не удалось
   * 
   * @param {string} Url 
   * @param {object} Data не обязательный параметр, объект с данными для POST-запроса, 
   * будет преобразован в JSON-строку - JSON.stringify(Data)
   * @param {object} Headers не обязательный параметр, объект с Http-заголовками для запроса
   * @param {number} Count служебный параметр - счетчик неудачных вызовов
   * @returns {Promise} промис, содержащий объект с данными
   */
  post(Url, Data = {}, Headers = {}, Count = 0) {
    // эта функция вызывает себя рекурсивно, прибавляя при каждом вызове 1 к Count
    // если кол-во превысит MAX_CALL_COUNT, то выбрасываем исключение
    if (Count >= this.MAX_CALL_COUNT) {
      throw new ErrorMaxCallCount("[FetchViaJwt.post]");
    }
    return this.fetchViaJwt(Url, "POST", Data, Headers)
      .then(this.onResponseCheck401)
      .catch(this.refreshTokensAndRepeatRequest(Url, Data, Headers, this.post, Count));
  }
  /**
   * получает данные методом POST с проверкой авторизации,
   * если Access токен просрочен, то повторно запрашивает JWT,
   * используя функцию fetchTokens,
   * если обновить токены не удалось
   * 
   * @param {string} Url 
   * @param {object} Data не обязательный параметр, объект с данными для PUT-запроса, 
   * будет преобразован в JSON-строку - JSON.stringify(Data)
   * @param {object} Headers не обязательный параметр, объект с Http-заголовками для запроса
   * @param {number} Count служебный параметр - счетчик неудачных вызовов
   * @returns {Promise} промис, содержащий объект с данными
   */
  put(Url, Data = {}, Headers = {}, Count = 0) {
    // эта функция вызывает себя рекурсивно, прибавляя при каждом вызове 1 к Count
    // если кол-во превысит MAX_CALL_COUNT, то выбрасываем исключение
    if (Count >= this.MAX_CALL_COUNT) {
      throw new ErrorMaxCallCount("[FetchViaJwt.put]");
    }
    return this.fetchViaJwt(Url, "PUT", Data, Headers)
      .then(this.onResponseCheck401)
      .catch(this.refreshTokensAndRepeatRequest(Url, Data, Headers, this.post, Count));
  }
  /**
   * получает данные методом POST с проверкой авторизации,
   * если Access токен просрочен, то повторно запрашивает JWT,
   * используя функцию fetchTokens,
   * если обновить токены не удалось
   * 
   * @param {string} Url 
   * @param {object} Data не обязательный параметр, объект с данными для DELETE-запроса, 
   * будет преобразован в JSON-строку - JSON.stringify(Data)
   * @param {object} Headers не обязательный параметр, объект с Http-заголовками для запроса
   * @param {number} Count служебный параметр - счетчик неудачных вызовов
   * @returns {Promise} промис, содержащий объект с данными
   */
  delete(Url, Data = {}, Headers = {}, Count = 0) {
    // эта функция вызывает себя рекурсивно, прибавляя при каждом вызове 1 к Count
    // если кол-во превысит MAX_CALL_COUNT, то выбрасываем исключение
    if (Count >= this.MAX_CALL_COUNT) {
      throw new ErrorMaxCallCount("[FetchViaJwt.put]");
    }
    return this.fetchViaJwt(Url, "DELETE", Data, Headers)
      .then(this.onResponseCheck401)
      .catch(this.refreshTokensAndRepeatRequest(Url, Data, Headers, this.post, Count));
  }

  /**
   * функция, которая принимает аргументом объект ответа,
   * предназначена для вызова в блоке then Promise после получения ответа от сервера,
   * проверяет ответ на содержание статуса 401,
   * если статус обнаружен, то выбрасывает объект ошибки - throw new Error401();
   * если статус не 401, то продолжает выполнение, 
   * возвращая результирующий промис return Resp.json();
   * 
   * @param {object} Resp
   * @returns {Promise}
   */
  onResponseCheck401(Resp) {
    debugPrint(Resp, "onResponseCheck401");
    if (checkFetchResponseStatus(Resp, HTTP_UNAUTHORIZED_CODE)) {
      throw new Error401();
    }
    return Resp.json();
  }

  /**
   * возвращает функцию, 
   * которая принимает аргументом ошибку 
   * и предназначена для вызова при возникновении catch у Promise во время неудачного вызова,
   * она проверяет статус ответа на 401 ошибку (не авторизован),
   * если ошибка 401, то запрашивает обновление токенов и повторяет основной запрос,
   * иначе выбрасывает исключение с полученной ошибкой дальше,
   * возвращать функцию нужно, что бы была возможность передать аргументы Url, Func, Count
   * 
   * @param {string} Url адрес запроса
   * @param {object} Data не обязательный параметр, объект с данными для POST-запроса, 
   * будет преобразован в JSON-строку - JSON.stringify(Data)
   * @param {object} Headers не обязательный параметр, объект с Http-заголовками для запроса
   * @param {function} Func функция, которая выполняет запрос 
   * и из которой произошел вызов этого обновления токенов
   * @param {number} Count кол-во повторов (кол-во текущих неудачных вызовов)
   * @returns {function}
   */
  refreshTokensAndRepeatRequest(Url, Data, Headers, Func, Count) {
    return (ErrResp) => {
      console.log("[refreshTokensAndRepeatRequest] catch => ErrResp: ", ErrResp);
      // если ошибка не Error401, значит это не наша ошибка, выбрасываем дальше
      if (!(ErrResp instanceof Error401)) {
        throw ErrResp;
      }
      // если на запрашиваемом ресурсе не прошла авторизация (ответ 401),
      // делаем запрос на получение новых токенов
      return this.fetchTokens().then((Tokens) => {
        debugPrint(Tokens, "refreshTokensAndRepeatRequest", true);
        this.setAccessToken(Tokens[this.JWT_ACCESS_TOKEN_NAME]);
        this.setRefreshToken(Tokens[this.JWT_REFRESH_TOKEN_NAME]);
        // при удачном получении новых токенов рекурсивно вызываем функцию,
        // в которой произошел вызов этого обновления
        return Func.call(this, Url, Data, Headers, Count + 1);
      });
    };
  }

  getAccessTokenDefault() {
    return getCookie(this.JWT_ACCESS_TOKEN_NAME); // BEARER
    // return localStorage.getItem(this.JWT_ACCESS_TOKEN_NAME);
  }
  setAccessTokenDefault(AccessToken) {
    setCookie(this.JWT_ACCESS_TOKEN_NAME, AccessToken); // BEARER
    // localStorage.setItem(this.JWT_ACCESS_TOKEN_NAME, AccessToken);
  }
  getRefreshTokenDefault() {
    return localStorage.getItem(this.JWT_REFRESH_TOKEN_NAME);
  }
  setRefreshTokenDefault(RefreshToken) {
    localStorage.setItem(this.JWT_REFRESH_TOKEN_NAME, RefreshToken);
  }



  /**
   * обновление токенов,
   * отправляет на сервер запрос с Refresh токеном,
   * в ответе от сервера должен быть JSON-объект 
   * с парой новых токенов Access (Bearer) и Refresh,
   * эта функция не сохраняет токены в локальных хранилищах
   * 
   * @returns {Promise} промис с объектом, содержащим два новых токена
   */
  fetchTokensDefault() {
    const RefreshToken = this.getRefreshToken(JWT_REFRESH_TOKEN_NAME);
    return this
      .post(this.JWT_REFRESH_URL, { [this.JWT_REFRESH_TOKEN_NAME]: RefreshToken, })
      .then((Resp) => Resp.json());
  }

  /**
   * Сконфигурированный для CORS запросов fetch
   * @param {string} Url 
   * @returns {Promise}
   */
  fetchViaJwt(Url, Method = "GET", Data = {}, Headers = {}) {
    const AccessToken = this.getAccessToken(this.JWT_ACCESS_TOKEN_NAME); // BEARER
    if (!AccessToken) {
      return new Promise((res, rej) => {
        rej(new Error401("[fetch]"));
      });
    }
    // объединение всех заголовков,
    // приоритет имеет Content-Type и Authorization устанавливаемые автоматом как часть логики работы объекта FetchViaJwt,
    // они перезапишут эти заголовки, если их указать в Headers или this.CommonHeaders,
    // затем приоритет у Headers из аргументов функции, заголовки из Headers перезапишут такие же из this.CommonHeaders,
    // на последнем месте будут заголовки установленные в this.CommonHeaders
    const AllHeaders = Object.assign({}, this.CommonHeaders, Headers || {}, {
      "Content-Type": "application/json",
      Authorization: "Bearer " + AccessToken,
      // [JWT_ACCESS_TOKEN_NAME]: AccessToken,
    });
    const Config = {
      method: Method, // *GET, POST, PUT, DELETE, etc.
      mode: "cors", // no-cors, *cors, same-origin
      cache: "default", // *default, no-cache, reload, force-cache, only-if-cached
      credentials: "include", // include, *same-origin, omit
      headers: AllHeaders,
      redirect: "follow", // manual, *follow, error
      referrerPolicy: "no-referrer", // no-referrer, *client
      body: JSON.stringify(Data || {}), // содержимое должно соответствовать указанному в заголовке "Content-Type"
    };

    return fetch(Url, Config);
  }

  /**
   * Вызывает fetch с методом GET 
   * формируя заголовок с использованием JWT ключей для авторизации
   * 
   * @param {string} Url 
   * @param {object} Data не обязательный параметр, каждая пара ключ значение,
   * будут добавлены к строке запроса ?key1=val1&key2=val2
   * @param {object} Headers 
   * @returns {Promise}
   */
  getViaJwt(Url, Data = {}, Headers = {}) {
    const NewUrl = generateGetUrl(Url, Data);
    return this.fetchViaJwt(NewUrl, "GET", {}, Headers);
  }

  /**
   * Вызывает простой fetch с методом POST без использования JWT авторизации, 
   * если не передан объект Config, 
   * то все параметры будут установлены браузером по умолчанию
   * 
   * @param {string} Url обязательный параметр, Url-адрес запроса
   * @param {object} Data не обязательный параметр, объект с данными для POST-запроса, 
   * будет преобразован в JSON-строку - JSON.stringify(Data)
   * @param {object} Headers не обязательный параметр, объект с Http-заголовками для запроса
   * @param {object} Config не обязательный параметр, объект стандартных настроек запроса fetch, 
   * кроме { headers, body }, которые будут установлены автоматически, 
   * заголовки и данные берутся из соответствующих параметров этой функции
   * @returns {Promise}
   */
  fetch(Url, Data = {}, Headers = {}, Config = {}) {
    // объединение всех заголовков,
    // главный приоритет у Headers из аргументов функции, 
    // заголовки из Headers перезапишут такие же из this.CommonHeaders,
    // на последнем месте будут заголовки установленные в this.CommonHeaders
    const AllHeaders = Object.assign({}, this.CommonHeaders, Headers || {});
    const NewConfig = {
      method: Config.method || "GET", // *GET, POST, PUT, DELETE, etc.
      mode: Config.mode || "cors", // no-cors, *cors, same-origin
      cache: Config.cache || "default", // *default, no-cache, reload, force-cache, only-if-cached
      credentials: Config.credentials || "same-origin", // include, *same-origin, omit
      headers: AllHeaders,
      redirect: Config.redirect || "follow", // manual, *follow, error
      referrerPolicy: Config.referrerPolicy || "client", // no-referrer, *client
      body: JSON.stringify(Data), // содержимое должно соответствовать указанному в заголовке "Content-Type"
    };

    return fetch(Url, NewConfig);
  }

  /**
   * Вызывает простой fetch с методом GET без использования JWT авторизации, 
   * если не передан объект Config, 
   * то все параметры будут установлены браузером по умолчанию
   * 
   * @param {string} Url обязательный параметр, Url-адрес запроса
   * @param {object} Data не обязательный параметр, каждая пара ключ значение,
   * будут добавлены к строке запроса ?key1=val1&key2=val2
   * @param {object} Headers не обязательный параметр, объект с Http-заголовками для запроса
   * @param {object} Config не обязательный параметр, объект стандартных настроек запроса fetch, 
   * кроме { method, headers, body }, которые будут установлены автоматически, 
   * метод будет установлен в GET,
   * заголовки и данные берутся из соответствующих параметров этой функции
   * @returns {Promise}
   */
  simpleGet(Url, Data = {}, Headers = {}, Config = {}) {
    const NewUrl = generateGetUrl(Url, Data);
    this.fetch(NewUrl, {}, Headers, Object.assign({}, Config || {}, { method: "GET" }));
  }
  /**
   * Вызывает простой fetch с методом POST без использования JWT авторизации, 
   * если не передан объект Config, 
   * то все параметры будут установлены браузером по умолчанию
   * 
   * @param {string} Url обязательный параметр, Url-адрес запроса
   * @param {object} Data не обязательный параметр, объект с данными для POST-запроса, 
   * будет преобразован в JSON-строку - JSON.stringify(Data)
   * @param {object} Headers не обязательный параметр, объект с Http-заголовками для запроса
   * @param {object} Config не обязательный параметр, объект стандартных настроек запроса fetch, 
   * кроме { method, headers, body }, которые будут установлены автоматически, 
   * метод будет установлен в POST,
   * заголовки и данные берутся из соответствующих параметров этой функции
   * @returns {Promise}
   */
  simplePost(Url, Data = {}, Headers = {}, Config = {}) {
    this.fetch(Url, Data, Headers, Object.assign({}, Config || {}, { method: "POST" }));
  }
}

export default FetchViaJwt;