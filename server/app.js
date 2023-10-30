const express = require("express");
const app = express();
const authRoute = require("./router/authRoute.js");
const databaseconnect = require("./config/databaseConnect.js");
const cors = require("cors");
const cookieParser = require("cookie-parser");

databaseconnect();
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: [process.env.CLIENT_URL],
    credentials: true,
  })
);
// app.use(cors());

app.use("/api/auth/", authRoute);

app.use("/", (req, res) => {
  res.status(200).json({ data: "Server is Ready" });
});
module.exports = app;
