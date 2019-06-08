import express from 'express';
import bodyParser from 'body-parser';


import config from './util/config';
import router from './routes/index';
import sequelize from './util/database';

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
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
