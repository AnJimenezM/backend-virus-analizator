import  {Schema, model} from "mongoose";

const UserSchema = Schema({
   
    first_name:{
        type: String,
        required: true
    },
    last_name:{
        type: String,
        required: true
    },
    username: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    
    image: {
        type: String,
        default: "default_user.png"
    },
    created_at: {
        type: Date,
        default: Date.now
    }

});



export default model("User", UserSchema, "users");

// users nombre del modelo
// userschema nombre del esquema
//users nombre de la coleccion mongodb