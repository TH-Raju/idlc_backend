import { connect } from "mongoose";
import app from "./app.js";
import config from "./config/index.js";

async function server() {
  try {
    await connect(config.DB_URL);
    console.log(`Database connection successfully`);

    app.listen(config.port, () => {
      console.log(`Sever listening on port ${config.port}`);
    });
  } catch (err) {
    console.log("Failed to connect", err);
  }
}

server();
