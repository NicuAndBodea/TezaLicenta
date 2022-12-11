const LocalStrategy = require("passport-local").Strategy
const mongoose = require("mongoose")
const bcrypt = require("bcryptjs")

const User = require("../models/User")

module.exports = (passport) => {
    passport.use(new LocalStrategy({usernameField: 'email'},(email,password,done)=>{
        //MATCH USER
        User.findOne({email:email},(err,user)=>{
            //CASE ERROR
            if(err) return done(err)
            //CASE USER NOT FOUND IN DATABASE
            if(!user) return done(null, false, {message: "That email is not registered"})
            //CASE PASSWORD DID NOT MATCH
            bcrypt.compare(password, user.password, (err, isMatch) => {
              if(err) throw err

              if(isMatch){
                   return done(null, user)
              } else {
                   return done(null, false, {message: "Incorrect password"})
               }
              })
        })
    }))

    passport.serializeUser((user, done)=> {
        process.nextTick(()=> {
            return done(null, {id: user.id});
        });
    });

    passport.deserializeUser(function(user, done) {
        process.nextTick(function() {
            return done(null, user);
        });
    });
}