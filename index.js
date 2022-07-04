import chalk from 'chalk';
import express, { json} from 'express';
import joi from 'joi';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import {v4 as uuid} from 'uuid';

import db from './db.js';

const app = express();
app.use(json());
app.use(cors());
dotenv.config();

const port = process.env.PORT || 5000

app.post("/signin", async (request, response) => {

  const signInSchema = joi.object({
    email: joi.string().email().required(),
    password: joi.string().required()
  });
  const { error } = signInSchema.validate(request.body, {abortEarly: false});
    if(error){
        return response.sendStatus(422)
    }

  try {
    const user = await db.collection("users").findOne({email: request.body.email})
    if(!user) return response.sendStatus(404);
    if(user && bcrypt.compareSync(request.body.password, user.password)){
      const token = uuid();
      await db.collection("sessions").insertOne({token, userId: user._id})
      response.send({token, name: user.name});
    } else {
      return response.sendStatus(401)
    }
  } catch {
    return response.sendStatus(500);
  }
});


app.post("/signup", async (request, response) => {
    const {name, email, password, confirmPassword} = request.body

    const signUpSchema = joi.object({
        name: joi.string().required(),
        email: joi.string().email().required(),
        password: joi.string().required(),
        confirmPassword: joi.ref('password')
    })
    const { error } = signUpSchema.validate(request.body, {abortEarly: false});
    if(error){
        return response.sendStatus(422)
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