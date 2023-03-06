const { response } = require('express')
const bcrypt = require('bcrypt')
const User = require('../models/User')
const { generarJWT } = require('../helpers/jwt')

const registerController = async (req, res = response) => {

  const { name, email, password } = req.body

  try {

    // Verifica si el email no exista

    let isEmailExists = await User.findOne({ email })

    if(isEmailExists) return res.status(400).json({
      status: false, msg: 'EMAIL_ALREADY_EXISTS'
    })

    // Creamos usuario

    const newUser = new User(req.body)

    // Encriptar la contraseña

    const salt = await bcrypt.genSalt(10)

    newUser.password = await bcrypt.hash(password, salt)

    // Generar el JWT

    const token = await generarJWT(newUser.id, name)

    // Gardar el usuario en la DB

    await newUser.save()

    // Generar la respusta 

    return res.status(201).json({
      status: true,
      msg: "USER_REGISTER_SUCCESSFULLY",
      data: newUser,
      token: token
    })
  } catch (error) {
    console.log(error)
    return res.status(500).json({ status: false, msg: "ERROR_REGISTER_USER" })
  }

}

const loginController = (req, res = response) => {

  return res.json({ status: true, msg: "PASSED" })
}

const revalidateToken = () => {

}


module.exports = {
  registerController,
  loginController,
  revalidateToken
}