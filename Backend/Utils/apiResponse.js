export default class ApiResponse {
    constructor(data, statusCode,  message = "Success") {
    this.statusCode = statusCode;
    this.data = data;
    this.message = message;
  }
}