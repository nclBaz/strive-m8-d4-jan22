import createError from "http-errors"
import { verifyAccessToken } from "./tools.js"

export const JWTAuthMiddleware = async (req, res, next) => {
  console.log("COOKIES ", req.cookies)
  // 1. Check if accessToken is in cookies, if it is not --> 401
  if (!req.cookies.accessToken) {
    next(createError(401, "Please send access token in cookies"))
  } else {
    try {
      // 2. Extract the token from cookies
      const token = req.cookies.accessToken

      // 3. Verify token (verify expiration date and check signature integrity), if everything is fine we should get back the payload ({_id, role})

      const payload = await verifyAccessToken(token)

      // 4. If token is ok --> next

      req.user = {
        _id: payload._id,
        role: payload.role,
      }

      next()
    } catch (error) {
      console.log(error)
      // 5. If the token is NOT ok --> jsonwebtoken library should throw some errors, so we gonna catch'em and --> 401
      next(createError(401, "Token not valid!"))
    }
  }
}
