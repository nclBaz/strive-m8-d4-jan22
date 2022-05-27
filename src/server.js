import express from "express"
import mongoose from "mongoose"
import listEndpoints from "express-list-endpoints"
import cors from "cors"
import passport from "passport"
import cookieParser from "cookie-parser"
import usersRouter from "./api/users/index.js"
import { unauthorizedHandler, forbiddenHandler, catchAllHandler } from "./errorHandlers.js"
import googleStrategy from "./auth/googleOAuth.js"

const server = express()
const port = process.env.PORT || 3001

passport.use("google", googleStrategy)

// *********************************** MIDDLEWARES ********************************************
server.use(cors({ origin: "http://localhost:3000", credentials: true }))
server.use(cookieParser())
server.use(express.json())
server.use(passport.initialize())

// ************************************ ENDPOINTS *********************************************
server.use("/users", usersRouter)

// ********************************** ERROR HANDLERS ******************************************
server.use(unauthorizedHandler)
server.use(forbiddenHandler)
server.use(catchAllHandler)

mongoose.connect(process.env.MONGO_CONNECTION)

mongoose.connection.on("connected", () => {
  console.log("Mongo Connected!")
  server.listen(port, () => {
    console.table(listEndpoints(server))
  })
})
