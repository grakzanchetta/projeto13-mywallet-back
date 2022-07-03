import chalk from 'chalk';
import express, { json} from 'express';
import joi from 'joi';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';

import db from './db.js';

const app = express();
app.use(json());
app.use(cors());
dotenv.config();

const port = process.env.PORT || 5000

app.post("/sign-up", async (request, response) => {
    const {name, email, password, confirmPassword} = request.body

    const signUpSchema = joi.object({
        name: joi.string().required(),
        email: joi.string().required(),
        password: joi.string().required(),
        confirmPassword: joi.ref('password')
    })
    const { error } = signUpSchema.validate(request.body, {abortEarly: false});
    if(error){
        return response.sendStatus(422).send(chalk.bold.red('Erro ao validar o cadastro!'))
    }
    try {
        const SALT = 10;
        const passwordHash = bcrypt.hashSync(request.body.password, SALT);
        
        await db.collection("users").insertOne({
          name: request.body.name,
          email: request.body.email,
          password: passwordHash
        });
        return response.sendStatus(201);
      } catch (error) {
        return response.sendStatus(500);
      }   
});
app.listen(port, () => {
    console.log(chalk.bold.green(`Server running on port: ${port}`))
})