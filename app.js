import express from 'express';
import bodyParser from 'body-parser';


import config from './util/config';
import router from './routes/index';
import sequelize from './util/database';

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*'); 
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});
app.use(router);


sequelize
  .sync({
    //force: true,
  }) 
  .then(cart => {
    console.log(`Your port is ${config.PORT}`); 
    app.listen(parseInt(config.PORT));
  })
  .catch(err => {
    console.log(err);
  });
