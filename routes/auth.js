import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import {
	addRefreshToken,
	createUser,
	deleteRefreshToken,
	getRefreshToken,
	getUser,
} from "../config/database.js";
import { authenticateToken } from "../middlewares/cookies.js";

const router = express.Router();

router.post("/register", async (req, res) => {
	const { username, password } = req.body || {};

	if (!username && !password)
		return res.status(404).send({ msg: "username and password are required" });
	if (!username) return res.status(404).send({ msg: "username required" });
	if (!password) return res.status(404).send({ msg: "password required" });

	const user = await getUser(username);
	if (user)
		return res
			.status(409)
			.send({ msg: "user with this username already exists" });

	if (password.length < 8)
		return res
			.status(400)
			.send({ msg: "Password length must be greater than 8" });

	const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@.#$!%*?&])(?!.*\s).*$/;
	if (!regex.test(password))
		return res.status(400).send({
			msg: "Password must be a combination of lower/upper letter, numbers, and special characters",
		});

	// Create the user
	const hashedPassword = await bcrypt.hash(password, 10);

	const newUser = await createUser(username, hashedPassword);

	const accessToken = jwt.sign(newUser, process.env.JWT_ACCESS_SECRET, {
		expiresIn: "15m",
	});
	const refreshToken = jwt.sign(newUser, process.env.JWT_REFRESH_SECRET, {
		expiresIn: "7d",
	});

	res.cookie("accessToken", accessToken, {
		httpOnly: true,
		secure: true,
		maxAge: 15 * 60 * 1000, // 15 minutes
		path: "/admin",
		secure: process.env.NODE_ENV === "production",
		sameSite: "lax",
	});
	res.cookie("refreshToken", refreshToken, {
		httpOnly: true,
		secure: true,
		maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
		path: "/admin",
		secure: process.env.NODE_ENV === "production",
		sameSite: "lax",
	});

	await addRefreshToken(newUser.id, refreshToken);

	res.status(201).send(newUser);
});

router.post("/login", async (req, res) => {
	const { username, password } = req.body || {};
	if (!username && !password)
		return res.status(404).send({ msg: "username and password are required" });
	if (!username) return res.status(404).send({ msg: "username required" });
	if (!password) return res.status(404).send({ msg: "password required" });

	const user = await getUser(username);
	if (!user)
		return res
			.status(404)
			.send({ msg: "user with this username doesn't exists" });

	const samePassword = bcrypt.compare(password, user.hashed_password);

	if (!samePassword) return res.status(401).send({ msg: "Wrong password" });

	const accessToken = jwt.sign(user, process.env.JWT_ACCESS_SECRET, {
		expiresIn: "15m",
	});

	const refreshToken = jwt.sign(user, process.env.JWT_REFRESH_SECRET, {
		expiresIn: "7d",
	});

	res.cookie("accessToken", accessToken, {
		httpOnly: true,
		secure: true,
		maxAge: 15 * 60 * 1000, // 15 minutes
		path: "/admin",
		secure: process.env.NODE_ENV === "production",
		sameSite: "lax",
	});
	res.cookie("refreshToken", refreshToken, {
		httpOnly: true,
		secure: true,
		maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
		path: "/admin",
		secure: process.env.NODE_ENV === "production",
		sameSite: "lax",
	});
	await addRefreshToken(user.id, refreshToken);
	res.sendStatus(200);
});

router.get("/dashboard", authenticateToken, (req, res) => {
	res.sendStatus(200);
});

router.post("/refresh-token", async (req, res) => {
	const { refreshToken } = req.cookies || {};
	if (!refreshToken)
		return res.status(401).sned({ msg: "No refresh token provided" });

	try {
		const oldPayload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
		const token = await getRefreshToken(refreshToken);
		if (!token)
			return res
				.status(401)
				.send({ msg: "Invalid refresh token from the database" });

		// check if the token is for the same user
		if (oldPayload.id !== token.user_id) {
			return res.status(401).send({ msg: "this is not your refresh token" });
		}

		await deleteRefreshToken(token.token);

		const payload = {
			id: oldPayload.id,
			username: oldPayload.username,
			hashed_password: oldPayload.hashed_password,
		};

		const newAccessToken = jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
			expiresIn: "15m",
		});
		const newRefreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
			expiresIn: "7d",
		});

		res.cookie("accessToken", newAccessToken, {
			httpOnly: true,
			secure: true,
			maxAge: 15 * 60 * 1000, // 15 minutes
			path: "/admin",
			secure: process.env.NODE_ENV === "production",
			sameSite: "lax",
		});
		res.cookie("refreshToken", newRefreshToken, {
			httpOnly: true,
			secure: true,
			maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
			path: "/admin",
			secure: process.env.NODE_ENV === "production",
			sameSite: "lax",
		});
		await addRefreshToken(token.user_id, newRefreshToken);

		return res.sendStatus(201);
	} catch (err) {
		return res.status(401).send({ msg: "Invalid refresh token", err: err });
	}
});

router.post("/logout", async (req, res) => {
	const { refreshToken } = req.cookies || {};
	if (!refreshToken)
		return res.send({ msg: "error refresh token not provided" });

	res.clearCookie("accessToken", {
		httpOnly: true,
		path: "/admin",
		secure: process.env.NODE_ENV === "production",
		sameSite: "lax",
	});
	res.clearCookie("refreshToken", {
		httpOnly: true,
		path: "/admin",
		secure: process.env.NODE_ENV === "production",
		sameSite: "lax",
	});

	await deleteRefreshToken(refreshToken);
	res.sendStatus(200);
});

export default router;
