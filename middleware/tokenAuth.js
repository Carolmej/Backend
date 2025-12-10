import jwt from "jsonwebtoken";

export default (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader)
            return res.status(401).json({ code: 401, message: "Token missing" });

        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Bloquear tokens temporales 2FA para acceder a rutas privadas
        if (decoded.is2FA === true) {
            return res.status(401).json({
                code: 401,
                message: "2FA token cannot be used for this request"
            });
        }

        req.tokenData = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ code: 401, message: "Invalid auth credentials" });
    }
};
