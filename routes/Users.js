const express = require("express")
const router = express.Router()
const { Users } = require("../models")
const bcrypt = require("bcryptjs")
const { sign } = require("jsonwebtoken")
const { validateToken } = require("../middlewares/AuthMiddleware")

router.post("/", async (req, res) => {
    const { username, password } = req.body
    bcrypt.hash(password, 10).then(async (hash) => {
        await Users.create({
            username,
            password: hash,
        })
        res.json("SUCCESS")
    })
})

router.post("/login", async (req, res) => {
    const { username, password } = req.body
    const user = await Users.findOne({ where: { username: username } })
    if (!user) {
        res.json({ error: "User Doesn't Exist" })
    }
    bcrypt.compare(password, user.password).then((match) => {
        if (!match) {
            res.json({ error: "Wrong Username And Password Combination" })
        } else {
            const accessToken = sign({ username: user.username, id: user.id }, "importantsecret")
            res.json({ token: accessToken, username: username, id: user.id })
        }
    })
})

router.get("/auth", validateToken, (req, res) => {
    res.json(req.user)
})

router.get("/basicinfo/:id", async (req, res) => {
    const id = req.params.id
    const basicInfo = await Users.findByPk(id, { attributes: { exclude: ["password"] } })
    res.json(basicInfo)
})

router.put("/changepassword", validateToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body
    const user = await Users.findOne({ where: { username: req.user.username } })
    bcrypt.compare(oldPassword, user.password).then((match) => {
        if (!match) {
            res.json({ error: "wrong password entered" })
        } else {
            bcrypt.hash(newPassword, 10).then(async (hash) => {
                const username = req.user.username
                await Users.update({ password: hash }, { where: { username } })
                res.json("SUCCESS")
            })
        }
    })
})

module.exports = router