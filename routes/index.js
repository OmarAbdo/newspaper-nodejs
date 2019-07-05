import express from 'express';
import userController from '../controllers/user/user';
import experimentalController from '../controllers/experimental';
import authenticationController from '../controllers/auth/authentication';


const router = express.Router();

//protected authenticated-users only routes
router.get('/api/v1/todos', authenticationController.checkToken, userController.getAllTodos);
router.get('/api/v1/todos/:id', authenticationController.checkToken, userController.getTodo);
router.post('/api/v1/todos', authenticationController.checkToken, userController.createTodo);
router.put('/api/v1/todos/:id', authenticationController.checkToken, userController.updateTodo);
router.delete('/api/v1/todos/:id', authenticationController.checkToken, userController.deleteTodo);


//authentication routes
router.post('/api/v1/authentication/signup', authenticationController.validate('signUp'), authenticationController.signUp);
// router.post('/api/v1/authentication/login',  authenticationController.logIn);
router.post('/api/v1/authentication/login', authenticationController.validate('logIn'), authenticationController.logIn);
// forgot password route

//Testing routes
router.get('/api/v1/test/authenticate', experimentalController.createJWT);
router.get('/api/v1/authentication/getdummyuser', authenticationController.dummyUser);
//router.get('/api/v1/authentication/login',  authenticationController.logIn);


export default router;