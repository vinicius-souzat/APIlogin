// imports
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

// Config JSON response
app.use(express.json())

// Models
const User = require('./models/User')

// Open Route - Public Route
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Bem vindo a nossa API!'})
})

// Private Route
app.get("/user/:id", checkToken, async (req, res) => {
        const id = req.params.id

    // check if user exists
    const user = await User.findById(id, '-password')

    if(!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado'})
    }

    res.status(200).json({ user })
})

function checkToken(req, res, next) {

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
        return res.status(401).json({ msg: 'Acesso negado!'})   
    }

    try {

        const secret = precess.env.SECRET

        jwt.verify(token, secret)

        next()
    } catch(error) {
        res.status(400).json({ msg: 'Token inválido!'})
    }
}


// Registrar User
app.post('/auth/register', async(req, res) => {

    const {name, email, password, confirmpassword} = req.body

    // Validações
    if(!name) {
        return res.status(422).json({ msg: 'O nome é obrigatorio!'})
    }

    if(!email) {
        return res.status(422).json({ msg: 'O email é obrigatorio!'})
    }

    if(!password) {
        return res.status(422).json({ msg: 'A senha é obrigatorio!'})
    }

    if(password !== confirmpassword) {
        return res.status(422).json({ msg: 'As senhas não conferem!'})
    }

    // Check if user existe
    const userExists = await User.findOne({ email: email})

    if(userExists) {
        return res.status(422).json({ msg: 'Por favor, utilize outro e-mail'})
    }

    // criar a senha
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // criar usuario
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {
        await user.save()

        res.status(201).json({ msg: 'Usuário criado com sucesso!'})
    } catch(erro) {

        res.status(500).json({ msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!'})
    }
})

// Login User
app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body

        // Validações
        if(!email) {
            return res.status(422).json({ msg: 'O email é obrigatorio!' })
        }
    
        if(!password) {
        return res.status(422).json({ msg: 'A senha é obrigatorio!' })
    }

    // check if user existe
    const user = await User.findOne({ email: email })

    if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado!' })
    }

    // check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword)  {
        return res.status(422).json({ msg: 'Senha invalida' })
    }

    try {   
        
        const secret = process.env.SECRET

        const token = jwt .sign(
            { 
            id: user._id,
            },
            secret,
        )

        res.status(200).json({ msg: 'Autenticalção realizada com sucesso', token})
    } catch (err) {
        console.log(error)

        res.status(500).json({ msg: 'Aconteceu um erro nop servidor, tente novamente mais tarde!',})
    }
})

app.post('/users', async (req, res) => {
    const { username, password } = req.body;
  
    if (!username || !password) {
      return res.sendStatus(400);
    }
  
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser =     await db.one('INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *', [usernamelog, hashedPassword]);
      res.sendStatus(201);
    } catch (error) {
      console.error(error);
      res.sendStatus(500);
    }
  });
  
  app.put('/users/:id', authenticateToken, async (req, res) => {
    const userId = req.params.id;
    const { username, password } = req.body;
  
    if (!username || !password) {
      return res.sendStatus(400);
    }
  
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      await db.oneOrNone('UPDATE users SET username = $1, password = $2 WHERE id = $3', [username, hashedPassword, userId]);
      res.sendStatus(200);
    } catch (error) {
      console.error(error);
      res.sendStatus(500);
    }
  });
  
  app.delete('/users/:id', authenticateToken, async (req, res) => {
    const userId = req.params.id;
  
    try {
      await db.none('DELETE FROM users WHERE id = $1', userId);
      res.sendStatus(200);
    } catch (error) {
      console.error(error);
      res.sendStatus(500);
    }
  });
  
  app.listen(3000, () => {
    console.log('Server listening on port 3000');
  });
  

//Credenciais
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose
    .connect(
        `mongodb+srv://${dbUser}:${dbPassword}@cluster0.slbmaco.mongodb.net/?retryWrites=true&w=majority`
    )
    .then(() => {
      app.listen(3000)
      console.log('Conectou ao banco!')
})
    .catch((err) => console.log(err))
