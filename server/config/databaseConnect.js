const mongoose = require("mongoose");
const MONGO_URI = process.env.MONGO_URI;
const databaseconnect = () => {
  mongoose
    .connect(MONGO_URI)
    .then((conn) => console.log(`connected to DB: ${conn.connection.host}`))
    .catch((err) => console.error(err.message));
};
module.exports = databaseconnect;
