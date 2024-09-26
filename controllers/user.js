import User from '../models/users.js'
import bcrypt from "bcrypt";
import {createToken} from '../services/jwt.js'
import fs from "fs";
import path from "path";
//Metodo prueba de usuario
export const testUser = (req, res) =>{
  return res.status(200).send({
      message: "Mensaje enviado desde el contenedor user.js",
      user: req.user
  });
}
// Método Registro de Usuarios
export const register = async (req, res) => {
  try {
    // Obtener los datos de la petición
    let params = req.body;

    // Validaciones de los datos obtenidos
    if (!params.first_name || !params.last_name || !params.email || !params.password || !params.username){
      return res.status(400).send({
        status: "error",
        message: "Faltan datos por enviar"
      });
    }

    // Crear el objeto de usuario con los datos que ya validamos
    let user_to_save = new User(params);

    // Busca si ya existe un usuario con el mismo email o username
    const existingUser = await User.findOne({
      $or: [
        { email: user_to_save.email.toLowerCase() },
        { username: user_to_save.username.toLowerCase() }
      ]
    });

    // Si encuentra un usuario, devuelve un mensaje indicando que ya existe
    if(existingUser) {
      return res.status(409).send({
        status: "error",
        message: "!El usuario ya existe!"
      });
    }

    // Cifra la contraseña antes de guardarla en la base de datos
    const salt = await bcrypt.genSalt(10); // Genera una sal para cifrar la contraseña
    const hashedPassword = await bcrypt.hash(user_to_save.password, salt); // Cifra la contraseña
    user_to_save.password = hashedPassword; // Asigna la contraseña cifrada al usuario

    // Guardar el usuario en la base de datos
    await user_to_save.save();

    // Devolver el usuario registrado
    return res.status(201).json({
      status: "created",
      message: "Registro de usuario exitoso",
      user_to_save
    });


  } catch (error) {
    // Manejo de errores
    console.log("Error en el registro de usuario:", error);
    // Devuelve mensaje de error
    return res.status(500).send({
      status: "error",
      message: "Error en el registro de usuario"
    });
  }
}

//Metodo de autenticacion de usuarios (login) usando jwt

export const login = async(req,res) =>{

  try {
    //Obtener los parametros del body
    let params = req.body;

    //Validar parametros username, password

    if(!params.email || !params.password){
      return res.status(400).send({
        status: "error",
        message: "Falta datos por enviar"
      })
    }

    //Buscar en la base de datos si el email recibido
    const user = await User.findOne({email: params.email.toLowerCase()});

    //Si no existe el usuario 
    if(!user){
      return res.status(400).send({
        status: "error",
        message: "Usuario no encontrado"
      });
    }

    //Comprobar la contraseña
    const validPassword = await  bcrypt.compare(params.password, user.password)


    //Si la contraseña es incorrecta
    if(!validPassword ){
      return res.status(401).send({
        status: "error",
        message: "Contraseña incorrecta"
      });
    }

    //Generar token de autenticacion
    const token = createToken(user);
    //Devolver Token y datos del usuario autenticado

    return res.status(200).json({
      status: "success",
      message: "Login exitoso",
      token,
      user:{
        id: user._id,
        username: user.username,
       first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
        image: user.image,
        created_at: user.created_at
      }
    });

    
   
  } catch (error) {
    // Manejo de errores
    console.log("Error en la autenticacion de usuario:", error);
    // Devuelve mensaje de error
    return res.status(500).send({
      status: "error",
      message: "Error en la autenticacion de usuario"
    });
  }

}

export const profile = async (req, res) =>{
  try {
    //Obtener el id del usuario desde los parametros de la url
    const userId = req.params.id;

    //Buscar al usuario en la BD y excluimos los datos que no queremos
    const user = await User.findById(userId);

    //verificar si el usuario no existe
    if(!user){
      return res.status(404).send({
        status: "success",
        message: "Usuario no encontrado"
      });
    }

    //Devolver la informacion del perfil del usuario
    return res.status(200).json({
      status: "success",
      user
    });

    
  } catch (error) {
    console.log("Error al obtener el perfil de usuario:", error)
    return res.status(500).send({
      status: "error",
      message: "Error al obtener el perfi de usuario"
    });
  }
}

// Método para actualizar los datos del usuario
export const updateUser = async (req, res) => {
  try {
    // Obtener la información del usuario a actualizar
    let userIdentity = req.user;
    let userToUpdate = req.body;

    // Eliminar campos que nos sobran (no vamos a actualizar)
    delete userToUpdate.iat;
    delete userToUpdate.exp;
    delete userToUpdate.role;

    // Comprobar si el usuario ya existe
    const users = await User.find({
      $or: [
        { email: userToUpdate.email },
        { username: userToUpdate.username },
      ]
    }).exec();

    // Verificar si el usuario está duplicado y evitar conflictos
    const isDuplicateUser = users.some(user => {
      return user && user._id.toString() !== userIdentity.userId;
    });

    if(isDuplicateUser) {
      return res.status(400).send({
        status: "error",
        message: "Error: solo se puede actualizar los datos del usuario logueado"
      });
    }

    // Cifrar la contraseña si se proporciona
    if(userToUpdate.password) {
      try {
        let pwd = await bcrypt.hash(userToUpdate.password, 10);
        userToUpdate.password = pwd;
      } catch (hashError) {
        return res.status(500).send({
          status: "error",
          message: "Error al cifrar la contraseña"
        });
      }
    } else {
      delete userToUpdate.password;
    }

    // Buscar y actualizar
    let userUpdated = await User.findByIdAndUpdate(userIdentity.userId, userToUpdate, { new: true });
    
    if(!userUpdated){
      return res.status(400).send({
        status: "error",
        message: "Error al actualizar el usuario"
      });
    }

    // Devolver la respuesta exitosa
    return res.status(200).send({
      status: "success",
      message: "Usuario actualizado correctamente",
      user: userUpdated
    });

  } catch (error) {
    console.log("Error al actualizar el usuario:", error)
    return res.status(500).send({
      status: "error",
      message: "Error al actualizar el usuario"
    });
  }
}

// Método para subir AVATAR (imagen de perfil) y actualizar el campo image del User

// Método para subir AVATAR (imagen de perfil) y actualizar el campo image del User
export const uploadAvatar = async (req, res) => {
  try {
    if(!req.file){
      return res.status(404).send({
        status: "error",
        message: "Error la petición no incluye la imagen"
      });
    }

    let image = req.file.originalname;
    const imageSplit = image.split(".");
    const extension = imageSplit[imageSplit.length -1];

    if(!["png", "jpg", "jpeg", "gif"].includes(extension)){
      const filePath = req.file.path;
      fs.unlinkSync(filePath);

      return res.status(404).send({
        status: "error",
        message: "Extensión del archivo inválida. Solo se permite: png, jpg, jpeg, gif"
      });
    }

    const fileSize = req.file.size;
    const maxFileSize = 1 * 1024 * 1024; // 1 MB

    if (fileSize > maxFileSize) {
      const filePath = req.file.path;
      fs.unlinkSync(filePath);

      return res.status(400).send({
        status: "error",
        message: "El tamaño del archivo excede el límite (máx 1 MB)"
      });
    }

    const userUpdated = await User.findOneAndUpdate(
      {_id: req.user.userId},
      { image: req.file.filename },
      { new: true}
    );

    if (!userUpdated) {
      return res.status(500).send({
        status: "error",
        message: "Error en la subida de la imagen"
      });
    }

    return res.status(200).json({
      status: "success",
      user: userUpdated,
      file: req.file
    });

  } catch (error) {
    console.log("Error al subir archivos", error)
    return res.status(500).send({
      status: "error",
      message: "Error al subir archivos"
    });
  }
}

// Método para mostrar el avatar (imagen de perfil)
export const avatar = async (req, res) =>{
  try {
    const file = req.params.file;
    const filePath = "./upload/avatars/" + file;

    fs.stat(filePath, (error) =>{
      if(error){
        return res.status(404).send({
          status: "error",
          message: "No existe la imagen"
        });
      }

      return res.sendFile(path.resolve(filePath));
    });

  } catch (error) {
    console.log("Error al mostrar imagen", error)
    return res.status(500).send({
      status: "error",
      message: "Error al mostrar imagen"
    });
  }
}