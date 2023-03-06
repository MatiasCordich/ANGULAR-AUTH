const jwt = require('jsonwebtoken')

const generarJWT = async ( id, name) => {
    
    const payload = { id, name }

    const token = jwt.sign(payload, process.env.SECRET_KEY, {expiresIn: '1h'})

    return token
}

module.exports = { generarJWT}