const mongoose = require('mongoose')


const dbConnection = async () => {
  
    try {
        await mongoose.connect( process.env.DB_URL, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        })

        console.log('DB Conectada')
    } catch (error) {
        console.log(error)
        throw new Error('Error al conectar la DB')
    }
}

module.exports = { dbConnection }