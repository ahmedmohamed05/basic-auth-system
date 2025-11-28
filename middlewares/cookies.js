import jwt from "jsonwebtoken";
export function authenticateToken(req, res, next) {
  const { accessToken } = req.cookies || {};
  if (!accessToken) return res.status(401).send({ msg: "Unauthenticated" });

  try {
    const user = jwt.verify(accessToken, process.env.JWT_ACCESS_SECRET);
    req.user = user;
    next();
  } catch (err) {
    res.status(401).send({ msg: "Access token expired" });
  }
}
