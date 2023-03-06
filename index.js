const express = require('express')
const cors = require('cors')
const authRouter = require('./routes/auth')
const { dbConnection } = require('./db/confing')
require('dotenv').config()

// Creamos el servidor/aplicacion de Express

const app = express()

// Middlewares

app.use(cors())

// Parseo del Body

app.use( express.json())


// Conectarse a la DB

dbConnection()

// Rutas

app.get('/',(req, res) => {
  res.status(202).send({
    msg: 'API funcionando'
  })
})

app.use('/api/auth', authRouter)


// Levantar el servidor

const PORT = process.env.PORT || 3200

app.listen(4000, () => {
  console.log(`Servidor corriendo en puerto http://localhost:${PORT}`)
})