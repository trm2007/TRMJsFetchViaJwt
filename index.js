import { generateGetUrl, checkFetchResponseStatus, getFetchResponseStatus } from "./Helpers";
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

export class ErrorHTTPStatus extends Error {
  constructor(Message = "", Status) {
    const Separator = Message ? " " : "";
    super(Message + Separator + "Код ответа сервера: " + Status);
    this.name = "ErrorHTTPStatus";
    this.status = Status;
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
    this.CheckBearerInHeaderFlag = false;
    /**
     * Флаг, указывает, что если код ответа не попадает в промежуток >= 200 && <300,
     * то выбрасывается исключние,
     * в то время как стандартное поведение fetch просто возвращает ответ
     */
    this.ErrorWhenNot2xxFlag = true;
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
   * Если этот флаг установить в true, то при запросе обновления Access токена,
   * в заголовке ответа будет проверяться наличие JWT_ACCESS_TOKEN_NAME,
   * и если он там присутсвует, то именно это значение вернется в объекте с новым токеном
   * 
   * @param {boolean} CheckBearerInHeaderFlag 
   */
  setCheckBearerInHeaderFlag(CheckBearerInHeaderFlag = true) {
    this.CheckBearerInHeaderFlag = CheckBearerInHeaderFlag;
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
   * Получает данные методом GET с проверкой авторизации,
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
   * @param {object} Config конфигурация обращения к серверу для стандартной JS-функции fetch
   * @returns {Promise} промис, содержащий объект с данными
   */
  get(Url, Data = null, Headers = {}, Config = {}) {
    return this.getJSON(Url, Data, Headers, Config);
  }
  /**
   * Получает данные методом GET с проверкой авторизации,
   * если Access токен просрочен, то повторно запрашивает JWT,
   * используя функцию fetchTokens, если обновить токены не удалось.
   * Получает данные в виде JSON-строки, 
   * преобразует их в стандартный объект JavaScript, и возвращает в Promise
   * 
   * @param {string} Url 
   * @param {object} Data не обязательный параметр, объект с данными для POST-запроса, 
   * все пары {ключ: значение} из объекта Data будут добавлены в строку GET-запроса
   * @param {object} Headers не обязательный параметр, объект с Http-заголовками для запроса,
   * заголовок Content-Type автоматически устанавливается в application/json
   * @param {object} Config конфигурация обращения к серверу для стандартной JS-функции fetch
   * @returns {Promise} промис, содержащий объект с данными
   */
  async getJSON(Url, Data = null, Headers = {}, Config = {}) {
    this.startBeforeHandlers();
    const Response = await this.getCounted(Url, "GET", Data, Headers, Config);
    const Result = await Response.json();
    this.startAfterHandlers(Result);
    return Result;
  }
  /**
   * Делает GET-запрос данные на сервер, в случае ошибки, точнее ответа 401.
   * вызывает refreshTokensAndRepeatRequest, и после повторно вызывает себя с этими же аргументами,
   * если ответ будет приходить с кодом 401 постоянно, 
   * 
   * @param {string} Url адрес запроса
   * @param {string} Method метод запроса, этот аргумент здесь нужен для совместимости с refreshTokensAndRepeatRequest
   * @param {object} Data данные (тело) зароса
   * @param {object} Headers заголовки запроса
   * @param {object} Config конфигурация обращения к серверу для стандартной JS-функции fetch
   * @param {number} Count - служебное поле, используется для подсчета кол-ва вызовов
   * @returns {Promise} необработанный ответ сервера, который возвращает стандарнтный fetch
   */
  getCounted(Url, Method = "GET", Data = null, Headers = {}, Config = {}, Count = 0) {
    console.log("[getCounted] =====> Method: ", Method);
    // эта функция вызывается рекурсивно, прибавляя при каждом вызове 1 к Count
    // если кол-во превысит MAX_CALL_COUNT, то выбрасываем исключение
    if (Count >= this.MAX_CALL_COUNT) {
      throw new ErrorMaxCallCount("[getCounted]");
    }
    // вызываем getViaJwt, которая добавит все поля из Data к Url-запроса
    return this.getViaJwt(Url, Data, Headers, Config)
      .then(this.onResponseCheck401) // .then(Resp => this.onResponseCheck401(Resp))
      .catch(this.refreshTokensAndRepeatRequest(Url, Method, Data, Headers, Config, this.getCounted, Count + 1));
  }

  /**
   * Получает данные с сервера, вызывая this.fetchCounted (которая в свою очередь вызываяет стандартный fetch,
   * предварительно проверяет токены и обновляет их при необходимости),
   * затем полученные результаты "прогоняет" через JSON парсинг и возвращает промис,
   * уже содержащий нормальный JS-объект вместо строки JSON.
   * Внимание! Сервер по этому адресу должен возвращать именно JSON-строку
   * 
   * @param {string} Url адрес запроса
   * @param {string} Method метод запроса
   * @param {object} Data данные (тело) зароса
   * @param {object} Headers заголовки запроса
   * @param {object} Config конфигурация обращения к серверу для стандартной JS-функции fetch
   * @returns {Promise}
   */
  async fetchJSON(Url, Method, Data = null, Headers = {}, Config = {}) {
    this.startBeforeHandlers();
    const Response = await this.fetchCounted(Url, Method, Data, Headers, Config);
    const Result = await Response.json();
    this.startAfterHandlers(Result);
    return Result;
  }
  /**
   * Запрашивает данные на сервере, в случае ошибки, точнее ответа 401.
   * вызывает refreshTokensAndRepeatRequest, и после повторно вызывает себя с этими же аргументами,
   * если ответ будет приходить с кодом 401 постоянно, 
   * то стоит проверка (ограничение) на кол-во рекурсивных вызовов - this.MAX_CALL_COUNT
   * 
   * @param {string} Url адрес запроса
   * @param {string} Method метод запроса
   * @param {object} Data данные (тело) зароса
   * @param {object} Headers заголовки запроса
   * @param {object} Config конфигурация обращения к серверу для стандартной JS-функции fetch
   * @param {number} Count - служебное поле, используется для подсчета кол-ва вызовов
   * @returns {Promise} необработанный ответ сервера, который возвращает стандарнтный fetch
   */
  fetchCounted(Url, Method, Data = null, Headers = {}, Config = {}, Count = 0) {
    // эта функция вызывается рекурсивно, прибавляя при каждом вызове 1 к Count
    // если кол-во превысит MAX_CALL_COUNT, то выбрасываем исключение
    if (Count >= this.MAX_CALL_COUNT) {
      throw new ErrorMaxCallCount("[fetchCounted]");
    }
    return this.fetchViaJwt(Url, Method, Data, Headers, Config)
      .then(this.onResponseCheck401)
      .then(Resp => {
        if (!this.ErrorWhenNot2xxFlag) {
          return Resp;
        }
        const Status = getFetchResponseStatus(Resp);
        if (Status < 200 || Status >= 300) {
          return Resp.json().then(Result => {
            // ***********************************************************************************
            // *** TO DO - data.errors так передается текст ошибки в CONT-е, нужно проработать ***
            // ***********************************************************************************
            const ErrMessage = Result.data.errors ? " " + Result.data.errors : " " + Result;
            throw new ErrorHTTPStatus("[fetchCounted]" + ErrMessage, Status);
          })
        }
        return Resp;
      })
      // this.refreshTokensAndRepeatRequest - возвращает функцию, поэтому в catch попадает именно функция-обработчик ошибки
      .catch(this.refreshTokensAndRepeatRequest(Url, Method, Data, Headers, Config, this.fetchCounted, Count + 1));
  }

  /**
   * Получает данные методом POST с проверкой авторизации,
   * если Access токен просрочен, то повторно запрашивает JWT,
   * используя функцию fetchTokens, если обновить токены не удалось.
   * Получает данные в виде JSON-строки, 
   * преобразует их в стандартный объект JavaScript и возвращает в Promise,
   * фактически это alias для this.fetchJSON(Url, "POST", Data, Headers, Config);
   * 
   * @param {string} Url адрес запроса
   * @param {object} Data не обязательный параметр, объект с данными для POST-запроса, 
   * будет преобразован в JSON-строку - JSON.stringify(Data) и добавлен как тело запроса
   * @param {object} Headers не обязательный параметр, объект с Http-заголовками для запроса,
   * заголовок Content-Type автоматически устанавливается в application/json
   * @param {object} Config конфигурация обращения к серверу для стандартной JS-функции fetch
   * @returns {Promise} промис, содержащий объект с данными
   */
  post(Url, Data = null, Headers = {}, Config = {}) {
    return this.fetchJSON(Url, "POST", Data, Headers, Config);
  }

  /**
   * Получает данные методом POST с проверкой авторизации,
   * если Access токен просрочен, то повторно запрашивает JWT,
   * используя функцию fetchTokens, если обновить токены не удалось.
   * Получает данные в виде JSON-строки, 
   * преобразует их в стандартный объект JavaScript и возвращает в Promise,
   * фактически это alias для this.fetchJSON(Url, "PUT", Data, Headers, Config);
   * 
   * @param {string} Url адрес запроса
   * @param {object} Data не обязательный параметр, объект с данными для PUT-запроса, 
   * будет преобразован в JSON-строку - JSON.stringify(Data) и добавлен как тело запроса
   * @param {object} Headers не обязательный параметр, объект с Http-заголовками для запроса,
   * заголовок Content-Type автоматически устанавливается в application/json
   * @param {object} Config конфигурация обращения к серверу для стандартной JS-функции fetch
   * @returns {Promise} промис, содержащий объект с данными
   */
  put(Url, Data = null, Headers = {}, Config = {}) {
    return this.fetchJSON(Url, "PUT", Data, Headers, Config);
  }

  /**
   * Получает данные методом POST с проверкой авторизации,
   * если Access токен просрочен, то повторно запрашивает JWT,
   * используя функцию fetchTokens, если обновить токены не удалось
   * Получает данные в виде JSON-строки, 
   * преобразует их в стандартный объект JavaScript и возвращает в Promise,
   * фактически это alias для this.fetchJSON(Url, "DELETE", Data, Headers, Config);
   * 
   * @param {string} Url адрес запроса
   * @param {object} Data не обязательный параметр, объект с данными для DELETE-запроса, 
   * будет преобразован в JSON-строку - JSON.stringify(Data) и добавлен как тело запроса
   * @param {object} Headers не обязательный параметр, объект с Http-заголовками для запроса,
   * заголовок Content-Type автоматически устанавливается в application/json
   * @param {object} Config конфигурация обращения к серверу для стандартной JS-функции fetch
   * @returns {Promise} промис, содержащий объект с данными
   */
  delete(Url, Data = null, Headers = {}, Config = {}) {
    return this.fetchJSON(Url, "DELETE", Data, Headers, Config);
  }

  /**
   * функция, которая принимает аргументом объект ответа,
   * предназначена для вызова в блоке then Promise после получения ответа от сервера,
   * проверяет ответ на содержание статуса 401,
   * если статус обнаружен, то выбрасывает объект ошибки - throw new Error401();
   * если статус не 401, то продолжает выполнение, 
   * возвращая полученный объект без изменения return Resp;
   * 
   * @param {object} Resp ответ сервера, который возвращает стандартная функция fetch
   * @returns {Promise} возвращает полученный объект Resp
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
   * @param {object} Resp ответ сервера, который возвращает стандартная функция fetch
   * @returns {Promise} возвращает полученный объект Resp
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
   * возвращать функцию нужно, что бы была возможность передать аргументы Url, Method, Data, Headers, Config, Count
   * 
   * @param {string} Url адрес запроса
   * @param {string} Method метод запроса (GET, POST, PUT...)
   * @param {object} Data не обязательный параметр, объект с данными для POST-запроса, 
   * будет преобразован в JSON-строку - JSON.stringify(Data)
   * @param {object} Headers не обязательный параметр, объект с Http-заголовками для запроса
   * @param {object} Config конфигурация обращения к серверу для стандартной JS-функции fetch
   * @param {function} Func функция, которая выполняет запрос 
   * и из которой произошел вызов этого обновления токенов
   * @param {number} Count - служебное поле, используется для подсчета кол-ва вызовов
   * @returns {function}
   */
  refreshTokensAndRepeatRequest(Url, Method, Data, Headers, Config, Func, Count) {
    return (ErrResp) => {
      // если ошибка не Error401, значит это не наша ошибка, выбрасываем дальше
      if (!(ErrResp instanceof Error401)) {
        throw ErrResp;
      }
      // если на запрашиваемом ресурсе не прошла авторизация (ответ 401),
      // делаем запрос на получение новых токенов
      return this.fetchTokens().then((Tokens) => {
        this.setAccessToken(Tokens[this.JWT_ACCESS_TOKEN_NAME]);
        this.setRefreshToken(Tokens[this.JWT_REFRESH_TOKEN_NAME]);
        // при удачном получении новых токенов рекурсивно вызываем функцию,
        // в которой произошел вызов этого обновления
        return Func.call(this, Url, Method, Data, Headers, Config, Count);
      });
    };
  }

  /**
   * Функция получения Access (BEARER) токена по умолчанию из cookie
   * 
   * @returns {string} Access (BEARER) токен
   */
  getAccessTokenDefault() {
    return getCookie(this.JWT_ACCESS_TOKEN_NAME); // BEARER
    // return localStorage.getItem(this.JWT_ACCESS_TOKEN_NAME);
  }
  /**
   * Функция установки Access (BEARER) токена по умолчанию в cookie
   * @param {string} AccessToken 
   */
  setAccessTokenDefault(AccessToken) {
    if (AccessToken) {
      setCookie(this.JWT_ACCESS_TOKEN_NAME, AccessToken); // BEARER
      // localStorage.setItem(this.JWT_ACCESS_TOKEN_NAME, AccessToken);
    }
  }
  /**
   * Функция получения Refresh токена по умолчанию из local storage
   * 
   * @returns {string} Refresh токен
   */
  getRefreshTokenDefault() {
    return localStorage.getItem(this.JWT_REFRESH_TOKEN_NAME);
  }
  /**
   * Функция установки Refresh токена по умолчанию в local storage
   * @param {string} AccessToken 
   */
  setRefreshTokenDefault(RefreshToken) {
    if (RefreshToken) {
      localStorage.setItem(this.JWT_REFRESH_TOKEN_NAME, RefreshToken);
    }
  }

  /**
   * Запрашивает новые токены и возвращает промис с объектом с токенами,
   * отправляет на сервер GET-запрос с Refresh токеном,
   * в ответе от сервера должна быть JSON-строка с объектом с токенами или токеном,
   * Refresh-токен может содержаться в httpOnly cookie, в этом случае JS никак не контролирует этот токен, только отправляет запросы,
   * где Refresh-токен в cookie прикрепляется автоматически.
   * Так же здесь Access (BEARER) токен может быть в заголовке ответа с именем [this.JWT_ACCESS_TOKEN_NAME].
   * Эта функция не сохраняет токены в локальных хранилищах!
   * 
   * @returns {Promise} промис с объектом, содержащим Access (BEARER) токен и, возможно, Refresh-токен
   */
  async fetchTokensDefault() {
    const RequestData = {};
    const RefreshToken = this.getRefreshToken();
    if (RefreshToken) { RequestData[this.JWT_REFRESH_TOKEN_NAME] = RefreshToken; }

    const Resp = await this
      .simpleGet(this.JWT_REFRESH_URL, RequestData);

    if (checkFetchResponseStatus(Resp, HTTP_PAGE_NOT_FOUND)) {
      throw new Error404("[fetchTokensDefault]");
    }
    // ********************************************************************************
    // ************ ВРЕМЕННОЕ РЕШЕНИЕ ПРОВЕРКИ BEARER В ЗАГОЛОВКЕ ОТВЕТА **************
    // ************************* ТАК РЕАЛИЗОВАНО В КОНТЕ ******************************
    // ********************************************************************************
    if (this.CheckBearerInHeaderFlag) {
      const BearerHeader = Resp.headers.get(this.JWT_ACCESS_TOKEN_NAME.toLocaleLowerCase());
      if (BearerHeader) {
        return new Promise(resolve => resolve({ [this.JWT_ACCESS_TOKEN_NAME]: BearerHeader }));
        // this.setAccessToken(BearerHeader);
      }
    }
    return Resp.json();
  }

  /**
   * Вызывает простой fetch без использования JWT авторизации, 
   * если не передан объект Config, 
   * то все параметры будут установлены браузером по умолчанию,
   * по умолчанию используется метод GET
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
   * fetch сконфигурированный для отправки запроса с JWT-ключом
   * Access (Bearer) в заголовке Authorization
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
   * @param {object} Config конфигурация обращения к серверу для стандартной JS-функции fetch
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