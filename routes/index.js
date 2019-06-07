import express from 'express';
import userController from '../controllers/user/user';
import experimentalController from '../controllers/experimental';

const router = express.Router();

router.get('/api/v1/todos', userController.getAllTodos);
router.get('/api/v1/todos/:id', userController.getTodo);
router.post('/api/v1/todos', userController.createTodo);
router.put('/api/v1/todos/:id', userController.updateTodo);
router.delete('/api/v1/todos/:id', userController.deleteTodo);

router.get('/api/v1/test/authenticate', experimentalController.createJWT);


export default router;