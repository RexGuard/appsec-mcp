import express from "express";
import cors from "cors";
import mysql from "mysql2/promise";
import { config } from "./config";

const app = express();
app.use(express.json());
app.use(cors({ origin: "*" }));

const pool = mysql.createPool({ host: config.dbHost, user: config.dbUser, database: "shop" });

app.get("/api/users", async (req, res) => {
  const name = req.query.name as string;
  const [rows] = await pool.query(`SELECT * FROM users WHERE name = '${name}'`);
  res.json(rows);
});

app.get("/hello", (req, res) => {
  res.send(`<h1>Hello ${req.query.name}</h1>`);
});

app.post("/api/orders", async (req, res) => {
  const [result] = await pool.execute("INSERT INTO orders (item) VALUES (?)", [req.body.item]);
  res.status(201).json(result);
});

app.listen(config.port, () => console.log(`listening on ${config.port}`));
