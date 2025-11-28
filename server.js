import express from "express";
import auth from "./routes/auth.js";
import cookieParser from "cookie-parser";

const app = express();
const PORT = process.env.SERVER_PORT;

app.use(express.json());
app.use(cookieParser());
app.use("/admin", auth);

app.listen(PORT, () => {
  console.log(`Server running on port: ${PORT}`);
});
