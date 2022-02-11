/* imports */
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const PORT = 3000;

const app = express()

// Config JSON response
app.use(express.json())

// Models
const User = require('./models/User')
const { response } = require('express')

// Open Route - Rota Publica
app.get('/', (req,res) =>{
    res.status(200).json({ msg: 'Bem vindo a nossa API!' })
})

// Private Route
app.get("/user/:id", checkToken, async (req,res) =>{

    const id = req.params.id

    // Check if user exist
    const user = await User.findById(id, '-password')

    if (!user){
        return res.status(404).json({ msg: 'Usuário não encontrado!'})
    }
    
    res.status(200).json({user})
})


function checkToken(req, res, next){

    const authHedaer = req.headers['authorization']
    const token = authHedaer && authHedaer.split(" ")[1]

    if(!token){

        return res.status(401).json({ msg: 'Acesso Negado!'})
    }
    try {

        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
        
    } catch (error) {
        res.status(400).json({ msg: 'Token invalido' })
    }

}

    

// Register User
app.post('/auth/register', async(req, res) =>{

    const {name, email, password, confirmpassword} = req.body

    //Validation
    if(!name){
        return res.status(422).json({msg: 'O nome é Obrigatório'})
    }

    if(!email){
        return res.status(422).json({msg: 'O email é Obrigatório'})
    }

    if(!password){
        return res.status(422).json({msg: 'O password é Obrigatório'})
    }

    if(password !== confirmpassword){
        return res.status(422).json({msg: 'As senhas não conferem'})
    }

    // Check if user exists

    const userExists = await User.findOne({email: email})

    if(userExists){
        return res.status(422).json({msg: 'Por favor, utilize outro email!'})

    }

    // Create Password

    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // Create user

    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try{
        await user.save()
        res.status(201).json({ msg: 'Usuario Criado com Sucesso!'})

    } catch(error){
        console.log(error)
        response.status(500).json({msg: 'Aconteceu um erro no server',})
    }
})


// Login user
app.post("/auth/login", async (req,res) =>{
    const {email, password} = req.body

    //Validation
    if(!email){
        return res.status(422).json({msg: 'O nome é Obrigatório'})
    }

    if(!password){
        return res.status(422).json({msg: 'O email é Obrigatório'})
    }

    // check if user exsists

    const user = await User.findOne({email: email})

    if(!user){
        return res.status(404).json({msg: 'Usuario não existe'})

    }

    // check if password natch

    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword){
        return res.status(404).json({ msg: 'Senha inválida'})
    }


    try {

        const secret = process.env.SECRET

        const token = jwt.sign({
            id: user._id,
        }, secret,)

        res.status(200).json({ mgs: 'Autenticação realizada com sucesso', token})

    } catch(error){
        console.log(error)
        response.status(500).json({msg: 'Aconteceu um erro no server',})
    }
    



})

// Credentials

const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.r6bbs.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`)
.then(() => {
    app.listen(PORT, () =>{
        console.log(`server Running in port: ${PORT}`);
    })
}).catch((err) => console.log(err))

