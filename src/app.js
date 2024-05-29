import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import rootRouter from "./routes/index.js";
import errorHandler from "./middlewares/errorHandler.js";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
// Enable CORS

app.use(express.static("src"));
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
    optionsSuccessStatus: 200,
    allowedHeaders: "Content-Type",
  })
);

app.use(errorHandler);
app.use("/api/v1", rootRouter);

app.get("/", (req, res) => {
  res.send("Server is working! YaY!");
});

app.all("*", (req, res) => {
  res.send("No Route Found.");
});

export default app;
