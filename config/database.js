import mysql from "mysql2";

const REQUIRED_ENV_VARS = [
	"MYSQL_HOST",
	"MYSQL_USER",
	"MYSQL_PASSWORD",
	"MYSQL_PORT",
	"MYSQL_DATABASE",
];

const missingEnvVars = REQUIRED_ENV_VARS.filter((key) => !process.env[key]);

if (missingEnvVars.length > 0) {
	throw new Error(
		`Missing required MySQL environment variables: ${missingEnvVars.join(", ")}`
	);
}

const refreshTokenTtlDays =
	Number.parseInt(process.env.REFRESH_TOKEN_TTL_DAYS ?? "7", 10) || 7;
const REFRESH_TOKEN_TTL_MS = refreshTokenTtlDays * 24 * 60 * 60 * 1000;

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
		[username, password]
	);

	const user = await getUser(username);
	if (!user) return null;
	const { hashed_password, ...safeUser } = user;
	return safeUser;
}

export async function addRefreshToken(userId, token) {
	const now = new Date();
	const expiresAt = new Date(now.getTime() + REFRESH_TOKEN_TTL_MS);

	const ret = await pool.query(
		"insert into refresh_tokens (user_id, token, created_at, expires_at) values (?, ?, ?, ?)",
		[userId, token, now, expiresAt]
	);

	return ret;
}

export async function getRefreshToken(token) {
	const [rows] = await pool.query(
		"select * from refresh_tokens where token = ?",
		[token]
	);
	return rows[0];
}

export async function deleteRefreshToken(token) {
	const ret = await pool.query(
		"delete from refresh_tokens where token = ? limit 1;",
		[token]
	);

	return ret;
}

export default pool;
