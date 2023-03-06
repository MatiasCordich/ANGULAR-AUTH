const { response } = require("express")
const jwt = require('jsonwebtoken')

const validarJWT = async (req, res = response, next) => {

    // Validar si existe el token
  
    const token = req.header('token')

    if(!token) return res.status(401).send({
      status: false,
      msg: "NO_TOKEN"
    })

    try {
        
        const payload = jwt.verify(token, process.env.SECRET_KEY)

        req.id = payload.id
        req.name = payload.name

    } catch (error) {
        return res.status(401).send({
            status: false,
            msg: "INVALID_TOKEN"
        })
    }

    next()
}

module.exports = {
    validarJWT
}