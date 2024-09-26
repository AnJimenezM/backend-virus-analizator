import { Router } from "express";
const router = Router();
import { testUser, register, login, profile, updateUser, uploadAvatar, avatar} from "../controllers/user.js";
import { ensureAuth } from "../middlewares/auth.js";
import multer from "multer";
import User from "../models/users.js"
import { checkEntityExists } from "../middlewares/checkEntityExists.js"


// Configuracion de subida de archivos 
const storage = multer.diskStorage({
  destination: (req, file, cb) =>{
      cb(null, "./upload/avatars")
  }, 
  filename: (req, file, cb) =>{
      cb(null, "avatar-"+Date.now()+ "-"+file.originalname);
  }
});
const uploads = multer({storage});
//definir las rutas

// Definir las rutas
router.post('/register', register);
router.post('/login', login);
router.get('/test-user', ensureAuth, testUser);
router.get('/profile/:id', profile, ensureAuth);
router.put('/update', ensureAuth, updateUser);
router.post('/upload-avatar', [ensureAuth, checkEntityExists(User, 'user_id'), uploads.single("file0")], uploadAvatar);
router.get('/avatar/:file', avatar);
// Exportar el Router
export default router;