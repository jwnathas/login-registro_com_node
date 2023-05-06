// imports que trabalharemos ao longo do projeto

require('dotenv').config()
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express()

//config JSON response
app.use(express.json())

//Moduls
const User = require('./models/User')

//open route - public route
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Bem vindo a nossa API!' })
})

//Private route
app.get('/user/:id',checkToken, async (req, res) => {

    const id = req.params.id
    //check if user exists
    const user = await User.findById(id, '-password')
    
    if (!user) {
        return res.status(404).json({ msg: 'Usuario não encontrado' })
    }

    res.status(200).json({user})
})

function checkToken(req, res, next){

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token) {
        return res.status(401).json({msg: "Acesso não autorizado"})
    }

    try {
        const secret = process.env.secret

        jwt.verify(token, secret)

        next()
    } catch (error) {
        res.status(400).json({msg: "Token inválido"})
    }

}

//Register User
app.post('/auth/register', async (req, res) => {

    const { name, email, password, confirmpassword } = req.body

    if (!name) {
        return res.status(422).json({ msg: 'O nome é obrigatório!' })
    }
    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatório!' })
    }
    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatório!' })
    }

    if (password != confirmpassword) {
        return res.status(422).json({ msg: 'As senhas não conferem.' })
    }
    //checar se o usuario existe
    const userExists = await User.findOne({ email: email })

    if (userExists) {
        return res.status(422).json({ msg: 'Porfavor Utilize outro email!' })
    }

    //criando a senha
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //create user
    const user = new User({
        name,
        email,
        password: passwordHash,
    })
    try {
        await user.save()
        res.status(201).json({ msg: "User criado com sucesso" })

    } catch (error) {
        res.status(500).json({ msg: "Aconteceu um erro no servidor" })
    }

})

//rota de login
app.post("/auth/login", async (req, res) => {

    const { email, password } = req.body
    //validations
    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatório!' })
    }
    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatório!' })
    }

    //checar se o usuario existe
    const user = await User.findOne({ email: email })

    if (!user) {
        return res.status(404).json({ msg: 'Usuario não encontrado' })
    }

    //checar se senha coicidem
    const checkPassword = await bcrypt.compare(password, user.password)

    if (!checkPassword) {
        return res.status(422).json({ msg: 'Senha inválida!' })
    }

    try {
        const secret = process.env.SECRET
        const token = jwt.sign(
        {
            id: user._id,
        },
            secret,
        )
        res.status(200).json({msg: "Autenticação realizada com sucesso!", token})
    } catch (error) {
        console.log(error)

        res.status(500).json({ msg: "Aconteceu um erro no servidor, tente novamente mais tarde" })
    }

})

//credenciais
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose  //é um biblioteca de Modelagem de Dados de Objeto para MongoDB e Node.js
    .connect(
        `mongodb+srv://jonathasbatista:${dbPassword}@cluster0.02rs3ne.mongodb.net/?retryWrites=true&w=majority`
    )
    .then(() => {
        console.log("Conectou ao banco!");
        app.listen(3000);
    })
    .catch((err) => console.log(err));
