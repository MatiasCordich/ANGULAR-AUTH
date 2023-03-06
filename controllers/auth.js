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

const loginController = async (req, res = response) => {

  const { email, password } = req.body

  try {

    // Validamos si el usuario existe mediante el email

    const isUserExists = await User.findOne({email})

    if(!isUserExists) return res.status(400).send({
      status: false,
      msg: "USER_DOES_NOT_EXISTS"
    })

    // Confirmar password

    const validPassword = await bcrypt.compare( password, isUserExists.password)

    if(!validPassword) return res.status(400).send({
      status: false,
      msg: "PASSWORD_INCORRECT"
    })

    // Generar el JWT

    const token = await generarJWT(isUserExists.id, isUserExists.name)

    // Respuesta del servicio

    return res.status(201).json({ 
      status: true, 
      msg: "LOGIN_SUCCESS",
      token: token,
      data: isUserExists
    })
    
  } catch (error) {
    return res.status(500).json({
      status: false,
      msg: "ERROR_LOGIN_USER"
    })
  }

  
}

const revalidateToken = async (req, res = response) => {

  const { id, name } = req

  // Hacer un nuevo token

  const token = await generarJWT(id, name)


  return res.status(201).json({
    status: true,
    id, 
    name,
    token
  })
}


module.exports = {
  registerController,
  loginController,
  revalidateToken
}