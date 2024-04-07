const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const path = require("path");
const cors = require("cors");
const routes = require("./routes");
require("dotenv").config({ path: path.resolve(process.cwd(), ".env") });
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(express.json());
const PORT = process.env.PORT;

// Connect to MongoDB
mongoose.connect(process.env.MONGO_DB_CONNECTION_STRING, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Middleware for parsing JSON
app.use(bodyParser.json());

app.use("/", routes);

app.get("/api/ping", (req, res) => {
  res.status(200).json({
    status: "success",
    message: "Pong",
  });
});

app.all("*", (req, res) => {
  res.status(404).json({
    status: "fail",
    message: `Route: ${req.originalUrl} does not exist on this server`,
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
