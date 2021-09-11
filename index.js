import { generateGetUrl, checkFetchResponseStatus, debugPrint } from "./Helpers";
import { getCookie, setCookie } from "./Cookies";

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
 * код ответа, что пользователь не авторизован
 */
const HTTP_UNAUTHORIZED_CODE = 401;
/**
 * код ответа, что страница (адрес) не найдена
 */
const HTTP_PAGE_NOT_FOUND = 404;

export class Error401 extends Error {
  constructor(Message = "") {
    const Separator = Message ? " " : "";
    super(Message + Separator + "Пользователь не авторизован!");
    this.name = "Error401";
  }
}

export class Error404 extends Error {
  constructor(Message = "") {
    const Separator = Message ? " " : "";
    super(Message + Separator + "Страница не найдена!");
    this.name = "Error404";
  }
}

export class ErrorMaxCallCount extends Error {
  constructor(Message = "") {
    const Separator = Message ? " " : "";
    super(Message + Separator + "Превышено количество допустимых попыток обновления токенов!");
    this.name = "ErrorMaxCallCount";
  }
}

export class ErrorNoAccessToken extends Error {
  constructor(Message = "") {
    const Separator = Message ? " " : "";
    super(Message + Separator + "Access токен локально не обнаружен!");
    this.name = "ErrorNoAccessToken";
  }
}
export class FetchViaJwt {
  /**
   * 
   * @param {string} JwtRefreshUrl адрес для запроса обновления токенов, 
   * это обязательный параметр, но если в объекте настройки передана функция fetchTokens, 
   * то здесь может быть пустая строка 
   * @param {object} params объект с настройками экземпляра FetchViaJwt: {
   * JwtAccessTokenName, // {string} под этим именем должен приходить с сервера и будет сохраняться access-токен, по умолчанию JWT_ACCESS_TOKEN_NAME = "BEARER"
   * JwtRefreshTokenName, // {string} под этим именем должен приходить с сервера и будет сохраняться refresh-токен, по умолчанию JWT_REFRESH_TOKEN_NAME = "REFRESH"
   * getAccessToken, // {function} можно передать функцию получения access-токена, по умолчанию берет из cookie 
   * setAccessToken, // {function} можно передать функцию установки access-токена, по умолчанию помещает в cookie
   * getRefreshToken, // {function} можно передать функцию получения refresh-токена, по умолчанию берет из localStorage
   * setRefreshToken, // {function} можно передать функцию установки refresh-токена, по умолчанию помещает в localStorage
   * fetchTokens, // {function} можно передать функцию запроса к api обновления токенов, должна вернуть промис содержащий объект с парой новых ключей 
   * MaxCallCount, // {number} ограничение на кол-во неудачных попыток запроса токенов, по умолчанию 3
   * BeforeHandlers, // {array} массив функций, вызываемых перед каждым запросом
   * AfterHandlers, // {array} массив функций, вызываемых после каждого запроса, аргументом в нее будет передаваться объект ответа от сервера
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
    BeforeHandlers,
    AfterHandlers,
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

    this.BeforeHandlers = BeforeHandlers || [];
    this.AfterHandlers = AfterHandlers || [];

    this.AuthorizationFlag = true;
  }

  /**
   * Включает или отключает флаг авторизации, т.е. флаг, который указывает, что с каждым запросом 
   * нужно добавлять заголовок Authorization с Bearer ключом.
   * По умолчанию AuthorizationFlag = true - заголовок передается
   * 
   * @param {boolean} AuthorizationFlag - значение, в которое будет установлен this.AuthorizationFlag, 
   * по умолчанию true
   */
  setAuthorizationFlag(AuthorizationFlag = true) {
    this.AuthorizationFlag = AuthorizationFlag;
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
   * запускает каждую функцию из массива this.BeforeHandlers
   */
  startBeforeHandlers() {
    if (this.BeforeHandlers.length) {
      this.BeforeHandlers.forEach(Item => Item());
    }
  }
  /**
   * запускает каждую функцию из массива this.AfterHandlers, передавая в нее аргумент ResponseResult
   * @param {*} ResponseResult - сюда нужно передать объект ответа от сервера, 
   * он будет передан в каждую вызываемую функцию из массива this.AfterHandlers
   */
  startAfterHandlers(ResponseResult) {
    if (this.AfterHandlers.length) {
      this.AfterHandlers.forEach(Item => Item(ResponseResult));
    }
  }

  /**
   * Получает данные методом POST с проверкой авторизации,
   * если Access токен просрочен, то повторно запрашивает JWT,
   * используя функцию fetchTokens, если обновить токены не удалось.
   * Получает данные в виде JSON-строки, 
   * преобразует их в стандартный объект JavaScript, и возвращает в Promise
   * фактически это alias для this.getJSON(Url, Data, Headers, Config);
   * 
   * @param {string} Url 
   * @param {object} Data не обязательный параметр, объект с данными для POST-запроса, 
   * все пары {ключ: значение} из объекта Data будут добавлены в строку GET-запроса
   * @param {object} Headers не обязательный параметр, объект с Http-заголовками для запроса,
   * заголовок Content-Type автоматически устанавливается в application/json
   * @param {number} Count служебный параметр - счетчик неудачных вызовов
   * @returns {Promise} промис, содержащий объект с данными
   */
  get(Url, Data = null, Headers = {}, Config = {}) {
    return this.getJSON(Url, Data, Headers, Config);
  }
  async getJSON(Url, Data = null, Headers = {}, Config = {}) {
    this.startBeforeHandlers();
    const Response = await this.getCounted(Url, Data, Headers, Config);
    const Result = await Response.json();
    this.startAfterHandlers(Result);
    return Result;
  }
  getCounted(Url, Data = null, Headers = {}, Config = {}, Count = 0) {
    // вызываем getViaJwt, которая добавит все поля из Data к Url-запроса
    return this.getViaJwt(Url, Data, Headers, Config)
      .then(this.onResponseCheck401) // .then(Resp => this.onResponseCheck401(Resp))
      .catch(this.refreshTokensAndRepeatRequest(Url, Data, Headers, Config, this.get, Count));
  }

  /**
   * Получает данные методом POST с проверкой авторизации,
   * если Access токен просрочен, то повторно запрашивает JWT,
   * используя функцию fetchTokens, если обновить токены не удалось.
   * Получает данные в виде JSON-строки, 
   * преобразует их в стандартный объект JavaScript и возвращает в Promise,
   * фактически это alias для this.postJSON(Url, Data, Headers, Config);
   * 
   * @param {string} Url 
   * @param {object} Data не обязательный параметр, объект с данными для POST-запроса, 
   * будет преобразован в JSON-строку - JSON.stringify(Data) и добавлен как тело запроса
   * @param {object} Headers не обязательный параметр, объект с Http-заголовками для запроса,
   * заголовок Content-Type автоматически устанавливается в application/json
   * @param {number} Count служебный параметр - счетчик неудачных вызовов
   * @returns {Promise} промис, содержащий объект с данными
   */
  post(Url, Data = null, Headers = {}, Config = {}) {
    return this.postJSON(Url, Data, Headers, Config);
  }
  async postJSON(Url, Data = null, Headers = {}, Config = {}) {
    this.startBeforeHandlers();
    const Response = await this.postCounted(Url, Data, Headers, Config);
    const Result = await Response.json();
    this.startAfterHandlers(Result);
    return Result;
  }
  postCounted(Url, Data = null, Headers = {}, Config = {}, Count = 0) {
    return this.fetchViaJwt(Url, "POST", Data, Headers, Config)
      .then(this.onResponseCheck401)
      .catch(this.refreshTokensAndRepeatRequest(Url, Data, Headers, Config, this.post, Count));
  }

  /**
   * Получает данные методом POST с проверкой авторизации,
   * если Access токен просрочен, то повторно запрашивает JWT,
   * используя функцию fetchTokens, если обновить токены не удалось.
   * Получает данные в виде JSON-строки, 
   * преобразует их в стандартный объект JavaScript и возвращает в Promise,
   * фактически это alias для this.putJSON(Url, Data, Headers, Config);
   * 
   * @param {string} Url 
   * @param {object} Data не обязательный параметр, объект с данными для PUT-запроса, 
   * будет преобразован в JSON-строку - JSON.stringify(Data) и добавлен как тело запроса
   * @param {object} Headers не обязательный параметр, объект с Http-заголовками для запроса,
   * заголовок Content-Type автоматически устанавливается в application/json
   * @param {number} Count служебный параметр - счетчик неудачных вызовов
   * @returns {Promise} промис, содержащий объект с данными
   */
  put(Url, Data = null, Headers = {}, Config = {}) {
    return this.putJSON(Url, Data, Headers, Config);
  }
  async putJSON(Url, Data = null, Headers = {}, Config = {}) {
    this.startBeforeHandlers();
    const Response = await this.putCounted(Url, Data, Headers, Config);
    const Result = await Response.json();
    this.startAfterHandlers(Result);
    return Result;
  }
  putCounted(Url, Data = null, Headers = {}, Config = {}, Count = 0) {
    return this.fetchViaJwt(Url, "PUT", Data, Headers, Config)
      .then(this.onResponseCheck401)
      .catch(this.refreshTokensAndRepeatRequest(Url, Data, Headers, Config, this.put, Count));
  }

  /**
   * Получает данные методом POST с проверкой авторизации,
   * если Access токен просрочен, то повторно запрашивает JWT,
   * используя функцию fetchTokens, если обновить токены не удалось
   * Получает данные в виде JSON-строки, 
   * преобразует их в стандартный объект JavaScript и возвращает в Promise,
   * фактически это alias для this.deleteJSON(Url, Data, Headers, Config);
   * 
   * @param {string} Url 
   * @param {object} Data не обязательный параметр, объект с данными для DELETE-запроса, 
   * будет преобразован в JSON-строку - JSON.stringify(Data) и добавлен как тело запроса
   * @param {object} Headers не обязательный параметр, объект с Http-заголовками для запроса,
   * заголовок Content-Type автоматически устанавливается в application/json
   * @param {number} Count служебный параметр - счетчик неудачных вызовов
   * @returns {Promise} промис, содержащий объект с данными
   */
  delete(Url, Data = null, Headers = {}, Config = {}) {
    return this.deleteJSON(Url, Data, Headers, Config);
  }
  async deleteJSON(Url, Data = null, Headers = {}, Config = {}) {
    this.startBeforeHandlers();
    const Response = await this.deleteCounted(Url, Data, Headers, Config);
    const Result = await Response.json();
    this.startAfterHandlers(Result);
    return Result;
  }
  deleteCounted(Url, Data = null, Headers = {}, Config = {}, Count = 0) {
    return this.fetchViaJwt(Url, "DELETE", Data, Headers, Config)
      .then(this.onResponseCheck401)
      .catch(this.refreshTokensAndRepeatRequest(Url, Data, Headers, Config, this.delete, Count));
  }

  /**
   * функция, которая принимает аргументом объект ответа,
   * предназначена для вызова в блоке then Promise после получения ответа от сервера,
   * проверяет ответ на содержание статуса 401,
   * если статус обнаружен, то выбрасывает объект ошибки - throw new Error401();
   * если статус не 401, то продолжает выполнение, 
   * возвращая полученный объект без изменения return Resp;
   * 
   * @param {object} Resp
   * @returns {Promise}
   */
  onResponseCheck401(Resp) {
    if (checkFetchResponseStatus(Resp, HTTP_UNAUTHORIZED_CODE)) {
      throw new Error401("[onResponseCheck401]");
    }
    return Resp;
  }
  /**
   * функция, которая принимает аргументом объект ответа,
   * предназначена для вызова в блоке then Promise после получения ответа от сервера,
   * проверяет ответ на содержание статуса 404,
   * если статус обнаружен, то выбрасывает объект ошибки - throw new Error404();
   * если статус не 404, то продолжает выполнение, 
   * возвращая полученный объект без изменения return Resp;
   * 
   * @param {object} Resp
   * @returns {Promise}
   */
  onResponseCheck404(Resp) {
    if (checkFetchResponseStatus(Resp, HTTP_PAGE_NOT_FOUND)) {
      throw new Error404("[onResponseCheck401]");
    }
    return Resp;
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
  refreshTokensAndRepeatRequest(Url, Data, Headers, Config, Func, Count) {
    return (ErrResp) => {
      // если ошибка не Error401, значит это не наша ошибка, выбрасываем дальше
      if (!(ErrResp instanceof Error401)) {
        throw ErrResp;
      }
      // эта функция вызывается рекурсивно, прибавляя при каждом вызове 1 к Count
      // если кол-во превысит MAX_CALL_COUNT, то выбрасываем исключение
      if (Count >= this.MAX_CALL_COUNT) {
        throw new ErrorMaxCallCount("[refreshTokensAndRepeatRequest]");
      }
      // если на запрашиваемом ресурсе не прошла авторизация (ответ 401),
      // делаем запрос на получение новых токенов
      return this.fetchTokens().then((Tokens) => {
        this.setAccessToken(Tokens[this.JWT_ACCESS_TOKEN_NAME]);
        this.setRefreshToken(Tokens[this.JWT_REFRESH_TOKEN_NAME]);
        // при удачном получении новых токенов рекурсивно вызываем функцию,
        // в которой произошел вызов этого обновления
        return Func.call(this, Url, Data, Headers, Config, Count + 1);
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
  async fetchTokensDefault() {
    const RefreshToken = this.getRefreshToken();
    const AccessToken = this.getAccessToken();
    const Resp = await this
      .simplePost(
        this.JWT_REFRESH_URL,
        { [this.JWT_REFRESH_TOKEN_NAME]: RefreshToken, [this.JWT_ACCESS_TOKEN_NAME]: AccessToken, },
        { "Authorization": "Bearer " + AccessToken, } // Headers
      );
    if (checkFetchResponseStatus(Resp, HTTP_PAGE_NOT_FOUND)) {
      throw new Error404("[fetchTokensDefault]");
    }
    return Resp.json();
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
  fetch(Url, Data = null, Headers = {}, Config = {}) {
    // объединение всех заголовков,
    // главный приоритет у Headers из аргументов функции, 
    // заголовки из Headers перезапишут такие же из this.CommonHeaders,
    // на последнем месте будут заголовки установленные в this.CommonHeaders
    const AllHeaders = Object.assign(
      {},
      this.CommonHeaders,
      { "Content-Type": "application/json", },
      Headers || {}
    );
    const FullConfig = {
      method: Config.method, // || "GET", // *GET, POST, PUT, DELETE, etc.
      mode: Config.mode, // || "cors", // no-cors, *cors, same-origin
      cache: Config.cache, // || "default", // *default, no-cache, reload, force-cache, only-if-cached
      credentials: Config.credentials, // || "same-origin", // include, *same-origin, omit
      headers: AllHeaders,
      redirect: Config.redirect, // || "follow", // manual, *follow, error
      referrerPolicy: Config.referrerPolicy, // || "origin", // no-referrer, *client
      body: Data ? JSON.stringify(Data) : undefined, // содержимое должно соответствовать указанному в заголовке "Content-Type"
    };

    return fetch(Url, FullConfig);
  }
  /**
   * fetch сконфигурированный для отправки JWT-ключа 
   * Access (Bearer) через заголовок Authorization
   * 
   * @param {string} Url - URL-адрес запроса
   * @param {string} Method - метод, по умолчанию GET
   * @param {object} Data - данные, в этом методе не могут быть переданы для GET-запросов, 
   * для всех остальных будут добавлены в тело запроса через JSON.stringify
   * @param {object} Headers - заголовки HTTP-запроса
   * @param {object} Config - объект конфигурации fetch, подробнее - https://developer.mozilla.org/ru/docs/Web/API/Fetch_API/Using_Fetch
   * @returns {Promise} промис будет содержать данные ответа сервера - объект Response
   */
  fetchViaJwt(Url, Method = "GET", Data = null, Headers = {}, Config = {}) {
    // если флаг AuthorizationFlag установлен в true,
    // значит нужно установить заголовок Authorization с ключом Bearer
    if (this.AuthorizationFlag) {
      const AccessToken = this.getAccessToken(this.JWT_ACCESS_TOKEN_NAME); // BEARER
      if (!AccessToken) {
        return new Promise((res, reject) => {
          reject(new ErrorNoAccessToken("[fetchViaJwt]"));
        });
      }
      Headers["Authorization"] = "Bearer " + AccessToken
    }
    Config.method = Method;
    return this.fetch(Url, Data, Headers, Config);
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
  getViaJwt(Url, Data = null, Headers = {}, Config = {}) {
    const NewUrl = generateGetUrl(Url, Data);
    return this.fetchViaJwt(NewUrl, "GET", null, Headers, Config);
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
  simpleGet(Url, Data = null, Headers = {}, Config = {}) {
    const NewUrl = generateGetUrl(Url, Data);
    return this.fetch(NewUrl, null, Headers, Object.assign({}, Config || {}, { method: "GET" }));
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
  simplePost(Url, Data = null, Headers = {}, Config = {}) {
    return this.fetch(Url, Data, Headers, Object.assign({}, Config || {}, { method: "POST" }));
  }
}

export default FetchViaJwt;