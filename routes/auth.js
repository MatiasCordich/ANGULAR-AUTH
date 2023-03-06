const { Router } = require('express')
const { check } = require('express-validator')
const { registerController, loginController, revalidateToken } = require('../controllers/auth')
const { validarCampos } = require('../middlewares/auth.validate')
const { validarJWT } = require('../middlewares/validar.jwt')

const router = Router()

router.post('/register', [
    check('name', 'El nombre es obligatorio').not().isEmpty(),
    check('email', 'El email es obligatorio').isEmail(),
    check('password', 'La contraseña es obligatoria').isLength({min: 6}),
    validarCampos
], registerController)

router.post('/', [
    check('email', 'El email es obligatorio').isEmail(),
    check('password', 'La contraseña es obligatoria').isLength({min: 6}),
    validarCampos
] ,loginController) 

router.get('/renew', validarJWT, revalidateToken)

module.exports = router