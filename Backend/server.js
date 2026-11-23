import express from "express";
import cookieParser from "cookie-parser";
import { notFound, errorHandler } from "./Middleware/error.Middleware.js";
import authRouter from "./Modules/Authentication/auth.route.js";

const port = 3000;
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use("/auth",
   authRouter);

//app.use(notFound);
//app.use(errorHandler);

app.listen(port, () => {
  console.log(`Server is running on port http://localhost:${port}`);
});
