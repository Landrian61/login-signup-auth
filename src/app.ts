import express from "express";
import mongoose from "mongoose";
import userSignUpRouter from "./api/auth/User/signup/userSignUp";
import adminSignUpRouter from "./api/auth/admin/signup/adminSignUp";
import adminLoginRouter from "./api/auth/admin/login/adminLogin";
import userLoginRouter from "./api/auth/User/login/userLogin";
import adminForgotPassWordRouter from "./api/auth/admin/changePassword/forgotPassword";
import adminChangePasswordRouter from "./api/auth/admin/changePassword/changePassword";
import userForgotPasswordRouter from "./api/auth/User/changePassword/forgotPassword";
import userChangePasswordRouter from "./api/auth/User/changePassword/changePassword";
import workspaceRouter from "./api/routes/workspaceRoutes";
require("dotenv").config();

const cors = require("cors");
const app = express();

//use cors
app.use(cors());

const port = process.env.PORT || 4000;

mongoose
  .connect(process.env.DATABASE_URL!)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Could not connect to MongoDB", err));

app.use(express.json());

app.use(
  "/auth/api_user",
  userSignUpRouter,
  userLoginRouter,
  userForgotPasswordRouter,
  userChangePasswordRouter
);
app.use(
  "/auth/api_admin",
  adminSignUpRouter,
  adminLoginRouter,
  adminForgotPassWordRouter,
  adminChangePasswordRouter
);
app.use("/api_workspace", workspaceRouter);

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
