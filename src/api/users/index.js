import express from "express"
import createError from "http-errors"
import { adminOnlyMiddleware } from "../../auth/admin.js"
import { JWTAuthMiddleware } from "../../auth/token.js"
import { authenticateUser, verifyRefreshTokenAndGenerateNewTokens } from "../../auth/tools.js"
import UsersModel from "./model.js"

const usersRouter = express.Router()

usersRouter.post("/", async (req, res, next) => {
  try {
    const user = new UsersModel(req.body)
    const { _id } = await user.save()
    res.status(201).send({ _id }) // { _id: "oijaosidjosajodjsaoi"}
  } catch (error) {
    next(error)
  }
})

usersRouter.get("/", JWTAuthMiddleware, adminOnlyMiddleware, async (req, res, next) => {
  try {
    const users = await UsersModel.find()
    res.send(users)
  } catch (error) {
    next(error)
  }
})

usersRouter.get("/me", JWTAuthMiddleware, async (req, res, next) => {
  try {
    const user = await UsersModel.findById(req.user._id)
    res.send(user)
  } catch (error) {
    next(error)
  }
})

usersRouter.put("/me", JWTAuthMiddleware, async (req, res, next) => {
  try {
    const modifiedUser = await UsersModel.findByIdAndUpdate(req.user._id, req.body)
  } catch (error) {
    next(error)
  }
})

usersRouter.delete("/me", JWTAuthMiddleware, async (req, res, next) => {
  await UsersModel.findByIdAndDelete(req.user._id)
})

usersRouter.get("/:userId", JWTAuthMiddleware, async (req, res, next) => {
  try {
  } catch (error) {
    next(error)
  }
})

usersRouter.put("/:userId", JWTAuthMiddleware, adminOnlyMiddleware, async (req, res, next) => {
  try {
  } catch (error) {
    next(error)
  }
})

usersRouter.delete("/:userId", JWTAuthMiddleware, adminOnlyMiddleware, async (req, res, next) => {
  try {
  } catch (error) {
    next(error)
  }
})

usersRouter.post("/login", async (req, res, next) => {
  try {
    // 1. Obtain credentials from req.body
    const { email, password } = req.body

    // 2. Verify credentials
    const user = await UsersModel.checkCredentials(email, password)

    if (user) {
      // 3. If credentials are ok --> generate an access token (JWT) and send it as a response

      const { accessToken, refreshToken } = await authenticateUser(user)
      res.send({ accessToken, refreshToken })
    } else {
      // 4. If credentials are not ok --> throw an error (401)
      next(createError(401, "Credentials are not ok!"))
    }
  } catch (error) {
    next(error)
  }
})

usersRouter.post("/refreshTokens", async (req, res, next) => {
  try {
    // 1. Receive the refresh token in req.body
    const { currentRefreshToken } = req.body

    // 2. Check validity of that token (check if it is not expired, check if it is not compromised, check if it is same as the one we store in db)
    const { accessToken, refreshToken } = await verifyRefreshTokenAndGenerateNewTokens(currentRefreshToken)
    // 3. If everything is fine --> generate a new pair of tokens (accessToken2 & refreshToken2)

    // 4. Send them back as a response
    res.send({ accessToken, refreshToken })
  } catch (error) {
    next(error)
  }
})

/*
FE

await fetch("/certainResource", {headers: {Authorization: accessToken}})

if(401){
  const {accessToken, refreshToken} = await fetch("/users/refreshTokens", {method: "POST", body: {currentRefreshToken: localStorage.getItem("refreshToken")}})
  if(res.ok) {
    localStorage.setItem("accessToken", accessToken)
    localStorage.setItem("refreshToken", refreshToken)

    await fetch("/certainResource", {headers: {Authorization: localStorage.getItem("accessToken")}})
  }

}

ALTERNATIVE WITH AXIOS --> https://www.npmjs.com/package/axios-auth-refresh

*/

export default usersRouter
