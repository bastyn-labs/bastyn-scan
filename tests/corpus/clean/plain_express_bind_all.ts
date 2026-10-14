import express from "express";

const app = express();
app.get("/health", (_req, res) => res.send("ok"));
app.listen(3000, "0.0.0.0");
