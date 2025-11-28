import jwt from "jsonwebtoken";
import mysql from "mysql2";

const pool = mysql
  .createPool({
    host: process.env.MYSQL_HOST,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    port: process.env.MYSQL_PORT,
    database: process.env.MYSQL_DATABASE,
  })
  .promise();

export async function getUser(username) {
  const [rows] = await pool.query("select * from users where username = ?", [
    username,
  ]);

  return rows[0];
}

export async function createUser(username, password) {
  await pool.query(
    "insert into users (username, hashed_password) values (?, ?)",
    [username, password],
  );

  const user = await getUser(username);
  return user;
}

export async function addRefreshToken(userId, token) {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

  const ret = await pool.query(
    "insert into refresh_tokens (user_id, token, created_at, expires_at) values (?, ?, ?, ?)",
    [userId, token, now, expiresAt],
  );

  return ret;
}

export async function getRefreshToken(token) {
  const [rows] = await pool.query(
    "select * from refresh_tokens where token = ?",
    [token],
  );
  return rows[0];
}

export async function deleteRefreshToke(token) {
  const ret = await pool.query(
    "delete from refresh_tokens where token = ? limit 1;",
    [token],
  );

  return ret;
}

export default pool;
