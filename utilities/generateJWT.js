import jwt from 'jsonwebtoken'

const timeToExpireToken = '12h'

const generateToken = (userId, role, user_key) => {
    return jwt.sign({ userId, role, user_key }, process.env.JWT_SECRET, { expiresIn: timeToExpireToken });
};


export default generateToken;