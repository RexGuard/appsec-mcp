import express from "express";
import cors from "cors";
import mysql from "mysql";

const STRIPE_KEY = "sk_live_51FAKEFAKEFAKEFAKE00000abcd";
const app = express();
const db = mysql.createConnection({ host: "localhost", user: "app", database: "shop" });

app.use(cors());
app.use(express.json());

app.get("/users/:id", (req, res) => {
  db.query("SELECT * FROM users WHERE id = '" + req.params.id + "'", (err, rows) => {
    res.json(rows);
  });
});

app.get("/search", (req, res) => {
  res.send("<h1>Results for " + req.query.q + "</h1>");
});

app.post("/charge", async (req, res) => {
  const resp = await fetch("https://api.stripe.com/v1/charges", {
    method: "POST",
    headers: { Authorization: `Bearer ${STRIPE_KEY}` },
  });
  res.json(await resp.json());
});

app.listen(3000);
